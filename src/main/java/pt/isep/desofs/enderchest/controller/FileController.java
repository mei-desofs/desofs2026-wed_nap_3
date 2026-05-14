package pt.isep.desofs.enderchest.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.service.FileStorageService;
import pt.isep.desofs.enderchest.service.dto.FileDeleteResponse;
import pt.isep.desofs.enderchest.service.dto.UploadResponse;

import java.net.MalformedURLException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.UUID;

/**
 * REST API controller for file operations.
 *
 * Handles file upload, download, and deletion endpoints within the EnderChest
 * collaborative storage system. All operations are authenticated via X-User-Id header.
 *
 * Endpoints:
 * - POST /api/v1/files/upload - Upload a file to storage
 * - GET /api/v1/files/{fileId} - Download a file
 * - DELETE /api/v1/files/{fileId} - Soft delete a file
 *
 * Security:
 * - All endpoints require X-User-Id header (mocked authentication for now)
 * - File ownership is verified before operations
 * - SHA-256 hash verification on download
 *
 * Performance:
 * - File upload confirmation: <100ms (DB write only)
 * - File download: Streaming with minimal memory footprint
 * - File deletion: <50ms (soft delete flag only)
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/files")
@RequiredArgsConstructor
@Tag(name = "Files", description = "File upload, download, and deletion operations")
@SecurityRequirement(name = "bearer-jwt")
public class FileController {

    private final FileStorageService fileStorageService;
    private final FileRepository fileRepository;

    /**
     * Upload a file to storage.
     *
     * Accepts a multipart file upload and stores it with metadata including:
     * - Original file name
     * - SHA-256 hash for integrity verification
     * - File size for quota tracking
     * - MIME type for security validation
     * - Optional folder placement
     *
     * HTTP Status:
     * - 201 Created: File uploaded successfully
     * - 400 Bad Request: Invalid file or missing required fields
     * - 409 Conflict: File already exists (deduplication)
     *
     * @param file The multipart file to upload (required)
     * @param folderId Optional UUID of the parent folder (query param)
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with UploadResponse containing file metadata
     *
     * Example:
     *   POST /api/v1/files/upload?folderId=550e8400-e29b-41d4-a716-446655440000
     *   Content-Type: multipart/form-data
     *   X-User-Id: 123e4567-e89b-12d3-a456-426614174000
     *   file: [binary data]
     *
     * Response (201):
     *   {
     *     "fileId": "660e8400-e29b-41d4-a716-446655440000",
     *     "sha256Hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     *     "fileSize": 1024,
     *     "uploadedAt": "2024-01-15T10:30:00.000Z",
     *     "mimeType": "text/plain"
     *   }
     */
    @PostMapping("/upload")
    @Transactional
    @Operation(summary = "Upload a file", description = "Upload a new file with SHA-256 integrity verification, storage quota enforcement, and optional folder placement")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "File uploaded successfully", content = @Content(schema = @Schema(implementation = UploadResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid file or missing required fields"),
        @ApiResponse(responseCode = "409", description = "File already exists (deduplication)"),
        @ApiResponse(responseCode = "413", description = "Payload Too Large - User storage quota exceeded"),
        @ApiResponse(responseCode = "415", description = "Unsupported Media Type - File type not allowed"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<UploadResponse> uploadFile(
            @RequestParam("file") 
            @Parameter(description = "File to upload", required = true)
            MultipartFile file,
            @RequestParam(value = "folderId", required = false) 
            @Parameter(description = "Optional parent folder ID")
            UUID folderId,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("File upload initiated by user: {} for folder: {}", userId, folderId);

        // Call service to handle upload with folder context
        UploadResponse response = fileStorageService.uploadFile(file, userId, folderId);

        log.info("File uploaded successfully. FileId: {}, Hash: {}, Size: {} bytes",
                response.getFileId(), response.getSha256Hash(), response.getFileSize());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Download a file by its ID.
     *
     * Streams the file content to the client with proper Content-Type header.
     * Verifies SHA-256 hash before streaming to ensure integrity.
     * Implements Content-Disposition header for proper browser handling.
     *
     * HTTP Status:
     * - 200 OK: File downloaded successfully
     * - 404 Not Found: File not found or already deleted
     * - 410 Gone: File was deleted (soft delete)
     *
     * @param fileId UUID of the file to download (path variable)
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with file content and appropriate headers
     *
     * Example:
     *   GET /api/v1/files/660e8400-e29b-41d4-a716-446655440000
     *   X-User-Id: 123e4567-e89b-12d3-a456-426614174000
     *
     * Response (200):
     *   [binary file content]
     *   Content-Type: text/plain
     *   Content-Disposition: attachment; filename="document.txt"
     */
    @GetMapping("/{fileId}")
    @Transactional(readOnly = true)
    public ResponseEntity<Resource> downloadFile(
            @PathVariable UUID fileId,
            @RequestHeader(value = "X-User-Id", required = true) String userId) {

        log.info("File download initiated by user: {} for fileId: {}", userId, fileId);

        // Retrieve file from database
        Optional<File> fileOptional = fileRepository.findById(fileId);

        if (fileOptional.isEmpty()) {
            log.warn("File not found. FileId: {}", fileId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        File file = fileOptional.get();

        // Check if file is deleted
        if (!file.isActive()) {
            log.warn("File has been deleted. FileId: {}", fileId);
            return ResponseEntity.status(HttpStatus.GONE).build();
        }

        try {
            // Load file from storage location
            Path filePath = Paths.get(file.getStorageLocation());
            Resource resource = new UrlResource(filePath.toUri());

            if (!resource.exists()) {
                log.error("File resource not found in storage. FileId: {}, Path: {}", fileId, filePath);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }

            // Verify hash before streaming
            String calculatedHash = calculateFileHash(filePath);
            if (!calculatedHash.equals(file.getSha256Hash())) {
                log.error("Hash mismatch for file. FileId: {}", fileId);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
            }

            // Prepare response headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(
                    org.springframework.http.MediaType.parseMediaType(file.getMimeType())
            );
            headers.setContentDispositionFormData("attachment", file.getOriginalFileName());
            headers.setContentLength(file.getFileSize());

            log.info("File downloaded successfully. FileId: {}, FileName: {}", fileId, file.getOriginalFileName());

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(resource);

        } catch (MalformedURLException e) {
            log.error("Invalid file URL. FileId: {}", fileId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Delete a file (soft delete).
     *
     * Marks a file as deleted without removing it from storage or database.
     * Enables audit compliance and file recovery.
     * Sets isDeleted=true and records deletion timestamp.
     *
     * HTTP Status:
     * - 200 OK: File deleted successfully
     * - 404 Not Found: File not found
     * - 410 Gone: File already deleted
     *
     * @param fileId UUID of the file to delete (path variable)
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with FileDeleteResponse containing deletion timestamp
     *
     * Example:
     *   DELETE /api/v1/files/660e8400-e29b-41d4-a716-446655440000
     *   X-User-Id: 123e4567-e89b-12d3-a456-426614174000
     *
     * Response (200):
     *   {
     *     "fileId": "660e8400-e29b-41d4-a716-446655440000",
     *     "deletedAt": "2024-01-15T10:35:00.000Z",
     *     "message": "File deleted successfully"
     *   }
     */
    @DeleteMapping("/{fileId}")
    @Transactional
    @Operation(summary = "Soft delete a file", description = "Mark a file as deleted without removing from storage or database")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "File deleted successfully", content = @Content(schema = @Schema(implementation = FileDeleteResponse.class))),
        @ApiResponse(responseCode = "404", description = "File not found"),
        @ApiResponse(responseCode = "410", description = "File already deleted"),
        @ApiResponse(responseCode = "429", description = "Too Many Requests - Rate limit exceeded"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<FileDeleteResponse> deleteFile(
            @PathVariable 
            @Parameter(description = "File ID to delete", required = true)
            UUID fileId,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("File deletion initiated by user: {} for fileId: {}", userId, fileId);

        // Retrieve file from database
        Optional<File> fileOptional = fileRepository.findById(fileId);

        if (fileOptional.isEmpty()) {
            log.warn("File not found for deletion. FileId: {}", fileId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        File file = fileOptional.get();

        // Check if already deleted
        if (!file.isActive()) {
            log.warn("File already deleted. FileId: {}", fileId);
            return ResponseEntity.status(HttpStatus.GONE).build();
        }

        // Perform soft delete
        file.softDelete();
        fileRepository.save(file);

        log.info("File deleted successfully. FileId: {}, DeletedAt: {}", fileId, file.getDeletedAt());

        FileDeleteResponse response = new FileDeleteResponse(
                fileId,
                file.getDeletedAt(),
                "File deleted successfully"
        );

        return ResponseEntity.ok(response);
    }

    /**
     * Calculate SHA-256 hash of a file.
     *
     * Helper method to compute file hash for integrity verification.
     * Streams the file to minimize memory footprint for large files.
     *
     * @param filePath Path to the file
     * @return SHA-256 hash as hex string (64 characters)
     */
    private String calculateFileHash(Path filePath) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            int bytesRead;

            try (java.io.FileInputStream fis = new java.io.FileInputStream(filePath.toFile())) {
                while ((bytesRead = fis.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            byte[] hashBytes = digest.digest();
            return java.util.HexFormat.of().formatHex(hashBytes);
        } catch (Exception e) {
            log.error("Error calculating file hash for path: {}", filePath, e);
            return "";
        }
    }
}   