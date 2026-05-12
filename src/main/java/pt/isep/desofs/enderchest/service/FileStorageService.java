package pt.isep.desofs.enderchest.service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.apache.tika.Tika;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import pt.isep.desofs.enderchest.config.ApplicationProperties;
import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.entity.FileVersion;
import pt.isep.desofs.enderchest.exception.security.FileUploadException;
import pt.isep.desofs.enderchest.exception.security.InvalidFileTypeException;
import pt.isep.desofs.enderchest.exception.security.PathTraversalAttemptException;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.repository.FileVersionRepository;
import pt.isep.desofs.enderchest.service.dto.FileResponse;
import pt.isep.desofs.enderchest.service.dto.UploadResponse;

/**
 * Enhanced FileStorageService with SHA-256 hashing, database persistence, and version tracking.
 * 
 * Implements SDR-NEW-11 (File Upload Logic) with:
 * - Streaming SHA-256 hashing (O(1) memory overhead)
 * - Deduplication via hash-based lookup
 * - Soft-delete audit trail
 * - Immutable version history
 * - Path traversal and MIME type validation
 * - Transactional database operations
 * 
 * Performance targets:
 * - Upload confirmation: <100ms (DB write only)
 * - Hash lookup (deduplication): <20ms
 * - File retrieval: <5ms
 * - Hash calculation: O(1) memory regardless of file size
 * 
 * @author Backend Architecture
 * @version 2.0
 */
@Slf4j
@Service
public class FileStorageService {

    private final Path rootLocation;
    private final ApplicationProperties props;
    private final Tika tika;
    private final FileRepository fileRepository;
    private final FileVersionRepository fileVersionRepository;

    /**
     * Constructor with dependency injection for repositories and configuration.
     * 
     * @param props Application configuration with storage settings
     * @param fileRepository Repository for File entity persistence
     * @param fileVersionRepository Repository for FileVersion entity persistence
     */
    public FileStorageService(
            ApplicationProperties props,
            FileRepository fileRepository,
            FileVersionRepository fileVersionRepository) {
        this.props = props;
        this.rootLocation = Paths.get(props.storage().basePath());
        this.fileRepository = fileRepository;
        this.fileVersionRepository = fileVersionRepository;
        this.tika = new Tika();
    }

    /**
     * Initialize storage directory.
     * Creates the root storage location if it doesn't exist.
     * Called automatically by Spring after bean construction.
     */
    @PostConstruct
    public void init() {
        try {
            Files.createDirectories(rootLocation);
            log.info("Initialized file storage at: {}", rootLocation);
        } catch (IOException e) {
            log.error("Failed to initialize storage location: {}", rootLocation, e);
            throw new FileUploadException("Could not initialize storage location: " + e.getMessage());
        }
    }

    /**
     * Upload a file with SHA-256 hashing, deduplication, and persistence.
     * 
     * Implements the complete upload workflow:
     * 1. Validates filename and detects path traversal attempts
     * 2. Validates MIME type using Apache Tika magic bytes
     * 3. Checks file size limits
     * 4. Calculates SHA-256 hash while streaming file content
     * 5. Checks for duplicate files (deduplication)
     * 6. Persists file metadata and creates initial version record
     * 7. Stores file on disk with restricted permissions (0600)
     * 
     * Security measures:
     * - Path traversal detection (.. sequences, leading /)
     * - MIME type validation against allowlist
     * - UUID-based stored filename (prevents enumeration)
     * - File permissions (0600 - owner read/write only)
     * 
     * Performance:
     * - SHA-256 calculated during file read (single pass)
     * - DigestInputStream prevents loading entire file in memory
     * - Database writes transactional and optimized
     * 
     * @param file MultipartFile uploaded by user
     * @param uploadedBy User ID or email (from JWT subject)
     * @return UploadResponse with file ID, hash, size, and metadata
     * @throws InvalidFileTypeException If MIME type not in allowlist
     * @throws PathTraversalAttemptException If path traversal detected
     * @throws FileUploadException If storage or hashing fails
     */
    @Transactional
    public UploadResponse uploadFile(MultipartFile file, String uploadedBy)
            throws InvalidFileTypeException, PathTraversalAttemptException, FileUploadException {
        
        try {
            // Step 1: Validate filename for null/empty
            String originalFilename = file.getOriginalFilename();
            if (originalFilename == null || originalFilename.trim().isEmpty()) {
                throw new FileUploadException("Filename cannot be null or empty");
            }

            // Step 2: Path traversal detection (T-05 mitigation)
            validatePathTraversal(originalFilename);

            // Step 3: Get file size and validate against limit
            long fileSize = file.getSize();
            long maxFileSize = props.storage().maxFileSizeInBytes();
            if (fileSize > maxFileSize) {
                throw new FileUploadException(
                    String.format("File size (%d bytes) exceeds maximum allowed (%d bytes)", fileSize, maxFileSize)
                );
            }

            // Step 4: Validate MIME type using Tika (T-06 mitigation)
            String detectedMimeType = tika.detect(file.getInputStream());
            if (!props.storage().allowedMimeTypes().contains(detectedMimeType)) {
                throw new InvalidFileTypeException(detectedMimeType, 
                    String.join(", ", props.storage().allowedMimeTypes()));
            }

            // Step 5: Calculate SHA-256 hash while storing file
            String sha256Hash = calculateSha256AndStoreFile(file, originalFilename);

            // Step 6: Deduplication check
            Optional<File> existingFile = fileRepository.findBySha256Hash(sha256Hash);
            if (existingFile.isPresent()) {
                File existing = existingFile.get();
                if (!existing.getIsDeleted()) {
                    // File already exists and not deleted - return existing file info
                    log.info("File deduplication detected: file with hash {} already exists", sha256Hash);
                    return createUploadResponse(existing);
                } else {
                    // File exists but was deleted - restore it
                    existing.restore();
                    fileRepository.save(existing);
                    log.info("Restored previously deleted file with hash {}", sha256Hash);
                    return createUploadResponse(existing);
                }
            }

            // Step 7: Persist file metadata to database
            String storedFileName = UUID.randomUUID().toString();
            Path storagePath = rootLocation.resolve(storedFileName).normalize().toAbsolutePath();

            File fileEntity = new File(
                originalFilename,
                storedFileName,
                sha256Hash,
                fileSize,
                detectedMimeType,
                uploadedBy,
                storagePath.toString()
            );

            File savedFile = fileRepository.save(fileEntity);
            log.debug("Persisted file entity: id={}, hash={}, size={}", savedFile.getId(), sha256Hash, fileSize);

            // Step 8: Create initial FileVersion entry for audit trail
            FileVersion initialVersion = new FileVersion(
                savedFile,
                1,
                sha256Hash,
                uploadedBy,
                "Initial upload"
            );
            fileVersionRepository.save(initialVersion);
            log.debug("Created initial file version: fileId={}, versionNumber=1", savedFile.getId());

            log.info("File uploaded successfully: id={}, name={}, hash={}, size={}, uploadedBy={}",
                    savedFile.getId(), originalFilename, sha256Hash, fileSize, uploadedBy);

            return createUploadResponse(savedFile);

        } catch (InvalidFileTypeException | PathTraversalAttemptException e) {
            // Re-throw security exceptions
            throw e;
        } catch (IOException e) {
            log.error("I/O error during file upload", e);
            throw new FileUploadException("Failed to process file: " + e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error during file upload", e);
            throw new FileUploadException("Unexpected error during upload: " + e.getMessage());
        }
    }

    /**
     * Retrieve a file by ID with integrity verification.
     * 
     * @param fileId UUID of the file to retrieve
     * @param requestedBy User ID making the request (for access control)
     * @return FileResponse with file content and metadata
     * @throws FileUploadException If file not found or access denied
     */
    @Transactional(readOnly = true)
    public FileResponse retrieveFile(UUID fileId, String requestedBy) throws FileUploadException {
        Optional<File> optionalFile = fileRepository.findByIdAndIsDeletedFalse(fileId);
        
        if (optionalFile.isEmpty()) {
            throw new FileUploadException("File not found or has been deleted");
        }

        File file = optionalFile.get();

        // Access control: file owner or admin
        if (!file.getUploadedBy().equals(requestedBy)) {
            log.warn("Access denied for user {} to file {}", requestedBy, fileId);
            throw new FileUploadException("Access denied");
        }

        try {
            // Read file from disk
            Path filePath = Paths.get(file.getStorageLocation());
            byte[] fileContent = Files.readAllBytes(filePath);

            // Verify hash for integrity
            String calculatedHash = calculateSha256(fileContent);
            if (!calculatedHash.equals(file.getSha256Hash())) {
                log.error("Hash mismatch for file {}: stored={}, calculated={}",
                        fileId, file.getSha256Hash(), calculatedHash);
                throw new FileUploadException("File integrity check failed");
            }

            return new FileResponse(file, fileContent);

        } catch (IOException e) {
            log.error("Failed to retrieve file {}", fileId, e);
            throw new FileUploadException("Failed to read file from storage: " + e.getMessage());
        }
    }

    /**
     * Soft delete a file (mark as deleted, keep content for recovery).
     * 
     * Creates a FileVersion entry documenting the deletion.
     * 
     * @param fileId UUID of the file to delete
     * @param deletedBy User ID performing the deletion
     * @throws FileUploadException If file not found or access denied
     */
    @Transactional
    public void deleteFile(UUID fileId, String deletedBy) throws FileUploadException {
        Optional<File> optionalFile = fileRepository.findByIdAndIsDeletedFalse(fileId);
        
        if (optionalFile.isEmpty()) {
            throw new FileUploadException("File not found or already deleted");
        }

        File file = optionalFile.get();

        // Access control: only file owner can delete
        if (!file.getUploadedBy().equals(deletedBy)) {
            log.warn("Delete access denied for user {} to file {}", deletedBy, fileId);
            throw new FileUploadException("Access denied");
        }

        try {
            // Perform soft delete
            file.delete();
            fileRepository.save(file);

            // Create FileVersion entry documenting deletion
            long nextVersionNumber = fileVersionRepository.countByFileId(fileId) + 1;
            FileVersion deleteVersion = new FileVersion(
                file,
                (int) nextVersionNumber,
                file.getSha256Hash(),
                deletedBy,
                "Deleted by user"
            );
            fileVersionRepository.save(deleteVersion);

            log.info("File soft-deleted: id={}, deletedBy={}", fileId, deletedBy);

        } catch (Exception e) {
            log.error("Failed to delete file {}", fileId, e);
            throw new FileUploadException("Failed to delete file: " + e.getMessage());
        }
    }

    /**
     * Validate filename for path traversal attempts.
     * Checks for:
     * - ".." sequences (parent directory)
     * - "/" or "\" characters (directory separators)
     * - Leading slashes (absolute paths)
     * - Null or empty filenames
     * 
     * @param filename The filename to validate
     * @throws PathTraversalAttemptException If validation fails
     */
    private void validatePathTraversal(String filename) throws PathTraversalAttemptException {
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
            log.warn("Path traversal attempt detected in filename: {}", filename);
            throw new PathTraversalAttemptException();
        }

        // Additional check: verify normalized path stays within root
        Path normalizedPath = rootLocation.resolve(filename).normalize();
        if (!normalizedPath.startsWith(rootLocation)) {
            log.warn("Normalized path escapes root directory: {}", filename);
            throw new PathTraversalAttemptException();
        }
    }

    /**
     * Calculate SHA-256 hash while storing file.
     * Uses DigestInputStream to compute hash in a single pass without loading
     * entire file into memory.
     * 
     * Implementation strategy:
     * - Read file through DigestInputStream (computes hash while reading)
     * - Generate UUID-based stored filename
     * - Write to disk with restricted permissions (0600)
     * - Return hex-encoded hash
     * 
     * @param file MultipartFile to hash and store
     * @param originalFilename Original filename (for context only)
     * @return SHA-256 hash as hex string (64 characters)
     * @throws IOException If file operations fail
     * @throws NoSuchAlgorithmException If SHA-256 algorithm not available
     */
    private String calculateSha256AndStoreFile(MultipartFile file, String originalFilename)
            throws IOException, NoSuchAlgorithmException {
        
        // Create MessageDigest for SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Generate UUID-based stored filename
        String storedFileName = UUID.randomUUID().toString();
        Path destinationFile = rootLocation.resolve(storedFileName).normalize().toAbsolutePath();

        // Verify destination is within root (final security check)
        if (!destinationFile.getParent().equals(rootLocation.toAbsolutePath())) {
            throw new PathTraversalAttemptException();
        }

        try (InputStream inputStream = file.getInputStream();
             DigestInputStream digestStream = new DigestInputStream(inputStream, digest)) {
            
            // Copy file to disk while computing hash
            Files.copy(digestStream, destinationFile);

            // Set restricted file permissions (0600 - owner read/write only)
            try {
                Files.setPosixFilePermissions(destinationFile, 
                    EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            } catch (UnsupportedOperationException e) {
                // POSIX not supported (e.g., Windows) - log but continue
                log.debug("POSIX file permissions not supported on this platform");
            }
        }

        // Get computed hash digest
        byte[] hashBytes = digest.digest();
        
        // Convert to hex string using HexFormat (Java 17+)
        String hexHash = HexFormat.of().formatHex(hashBytes);
        
        log.debug("SHA-256 hash calculated and file stored: hash={}, file={}, original={}",
                hexHash, storedFileName, originalFilename);

        return hexHash;
    }

    /**
     * Calculate SHA-256 hash of byte array.
     * Used for integrity verification when retrieving files.
     * 
     * @param data Byte array to hash
     * @return SHA-256 hash as hex string (64 characters)
     * @throws FileUploadException If hashing fails
     */
    private String calculateSha256(byte[] data) throws FileUploadException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(data);
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new FileUploadException("SHA-256 algorithm not available: " + e.getMessage());
        }
    }

    /**
     * Create UploadResponse DTO from File entity.
     * Encapsulates response data with essential metadata.
     * 
     * @param file File entity to convert
     * @return UploadResponse DTO
     */
    private UploadResponse createUploadResponse(File file) {
        return new UploadResponse(
            file.getId(),
            file.getSha256Hash(),
            file.getFileSize(),
            file.getUploadedAt(),
            file.getMimeType()
        );
    }

    /**
     * @deprecated Use {@link #uploadFile(MultipartFile, String)} instead.
     * Legacy method kept for backward compatibility.
     */
    @Deprecated(since = "2.0", forRemoval = false)
    public void save(MultipartFile file) throws InvalidFileTypeException, PathTraversalAttemptException {
        // Default user context for legacy calls
        uploadFile(file, "system");
    }
}