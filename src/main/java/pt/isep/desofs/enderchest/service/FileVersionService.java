package pt.isep.desofs.enderchest.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.entity.FileVersion;
import pt.isep.desofs.enderchest.exception.resource.FileNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.FileVersionNotFoundException;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.repository.FileVersionRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Service layer for file version management operations.
 *
 * This service provides business logic for:
 * - Listing all versions of a file (audit trail)
 * - Retrieving specific file versions
 * - Creating new file versions during file updates
 *
 * Design Principles:
 * - Immutable versions: Once created, versions cannot be modified
 * - Audit-compliant: All versions are tracked with timestamps and change descriptions
 * - Transactional: All write operations are atomic
 * - Performance-optimized: Uses repository indexes for efficient queries
 *
 * Performance Characteristics:
 * - listFileVersionsByFileId: O(log n + k) where k = number of versions
 * - getFileVersionById: O(log n) - primary key lookup
 * - createFileVersion: O(log n) - indexed insert
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class FileVersionService {

    private final FileVersionRepository fileVersionRepository;
    private final FileRepository fileRepository;

    /**
     * List all versions of a file.
     *
     * Returns complete version history for a file, sorted by version number.
     * Used for audit trails and version recovery scenarios.
     *
     * @param fileId UUID of the file
     * @return List of FileVersion entities (may be empty if no versions)
     * @throws FileNotFoundException if file not found or is deleted
     */
    @Transactional(readOnly = true)
    @NonNull
    public List<FileVersion> listFileVersionsByFileId(@NonNull UUID fileId) throws FileNotFoundException {

        // Verify file exists and is not deleted
        Optional<File> fileOptional = fileRepository.findById(fileId);

        if (fileOptional.isEmpty()) {
            log.warn("File not found. FileId: {}", fileId);
            throw new FileNotFoundException(fileId);
        }

        File file = fileOptional.get();

        if (file.getIsDeleted()) {
            log.warn("File has been deleted. FileId: {}", fileId);
            throw new FileNotFoundException("File has been deleted: " + fileId);
        }

        // Retrieve all versions for the file
        List<FileVersion> versions = fileVersionRepository.findByFileIdOrderByVersionNumberAsc(fileId);

        log.info("Found {} versions for file: {}", versions.size(), fileId);

        return versions;
    }

    /**
     * Get a specific file version by ID.
     *
     * Retrieves detailed information about a single file version.
     *
     * @param fileId UUID of the file
     * @param versionId UUID of the specific version
     * @return FileVersion entity
     * @throws FileNotFoundException if file not found or is deleted
     * @throws FileVersionNotFoundException if version not found
     */
    @Transactional(readOnly = true)
    @NonNull
    public FileVersion getFileVersionById(@NonNull UUID fileId, @NonNull UUID versionId)
            throws FileNotFoundException, FileVersionNotFoundException {

        // Verify file exists and is not deleted
        Optional<File> fileOptional = fileRepository.findById(fileId);

        if (fileOptional.isEmpty()) {
            log.warn("File not found. FileId: {}", fileId);
            throw new FileNotFoundException(fileId);
        }

        File file = fileOptional.get();

        if (file.getIsDeleted()) {
            log.warn("File has been deleted. FileId: {}", fileId);
            throw new FileNotFoundException("File has been deleted: " + fileId);
        }

        // Retrieve specific version
        Optional<FileVersion> versionOptional = fileVersionRepository.findById(versionId);

        if (versionOptional.isEmpty()) {
            log.warn("File version not found. VersionId: {}", versionId);
            throw new FileVersionNotFoundException(versionId);
        }

        FileVersion version = versionOptional.get();

        // Verify version belongs to the requested file
        if (!version.getFile().getId().equals(fileId)) {
            log.warn("Version does not belong to file. FileId: {}, VersionId: {}", fileId, versionId);
            throw new FileVersionNotFoundException("Version does not belong to file: " + versionId);
        }

        log.info("File version retrieved successfully. VersionId: {}, VersionNumber: {}, Hash: {}",
                versionId, version.getVersionNumber(), version.getSha256Hash());

        return version;
    }

    /**
     * Create a new file version.
     *
     * Creates a new version record for a file with provided metadata.
     * This is typically called during file updates to maintain version history.
     *
     * @param fileId UUID of the file
     * @param versionNumber Version number for this version
     * @param sha256Hash SHA-256 hash for integrity verification
     * @param modifiedBy User who made the modification
     * @param changeDescription Description of the change
     * @return Created FileVersion entity
     * @throws FileNotFoundException if file not found or is deleted
     */
    @Transactional
    @NonNull
    public FileVersion createFileVersion(@NonNull UUID fileId, int versionNumber, @NonNull String sha256Hash,
                                         @NonNull String modifiedBy, @NonNull String changeDescription)
            throws FileNotFoundException {

        // Verify file exists and is not deleted
        Optional<File> fileOptional = fileRepository.findById(fileId);

        if (fileOptional.isEmpty()) {
            log.warn("File not found. FileId: {}", fileId);
            throw new FileNotFoundException(fileId);
        }

        File file = fileOptional.get();

        if (file.getIsDeleted()) {
            log.warn("File has been deleted. FileId: {}", fileId);
            throw new FileNotFoundException("File has been deleted: " + fileId);
        }

        // Create new version
        FileVersion version = new FileVersion();
        version.setFile(file);
        version.setVersionNumber(versionNumber);
        version.setSha256Hash(sha256Hash);
        version.setModifiedAt(LocalDateTime.now());
        version.setModifiedBy(modifiedBy);
        version.setChangeDescription(changeDescription);

        // Save to database
        FileVersion savedVersion = fileVersionRepository.save(version);

        log.info("File version created successfully. VersionId: {}, FileId: {}, VersionNumber: {}",
                savedVersion.getId(), fileId, versionNumber);

        return savedVersion;
    }
}
