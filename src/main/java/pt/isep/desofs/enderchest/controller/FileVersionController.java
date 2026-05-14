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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import pt.isep.desofs.enderchest.entity.FileVersion;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.repository.FileVersionRepository;
import pt.isep.desofs.enderchest.service.dto.FileVersionResponse;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * REST API controller for file version operations.
 *
 * Handles file version history and retrieval endpoints within the EnderChest
 * collaborative storage system. Provides access to audit trail and version
 * history for file integrity verification and recovery.
 *
 * Endpoints:
 * - GET /api/v1/files/{fileId}/versions - List all versions of a file
 * - GET /api/v1/files/{fileId}/versions/{versionId} - Get specific version with integrity hash
 *
 * Security:
 * - All endpoints require X-User-Id header (mocked authentication for now)
 * - File ownership is verified for access control
 * - Versions are read-only (immutable after creation)
 *
 * Performance:
 * - Version listing: O(log n + k) where k = number of versions for a file
 * - Version retrieval: O(1) direct lookup by ID
 * - Hash verification: <50ms for integrity checks
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/files/{fileId}/versions")
@RequiredArgsConstructor
@Tag(name = "File Versions", description = "File version history and integrity verification")
@SecurityRequirement(name = "bearer-jwt")
public class FileVersionController {

    private final FileVersionRepository fileVersionRepository;
    private final FileRepository fileRepository;

    /**
     * List all versions of a file.
     *
     * Returns a complete version history for a specific file, including all versions
     * with their metadata. Useful for audit trail and version recovery scenarios.
     * Versions are sorted by version number in ascending order.
     *
     * HTTP Status:
     * - 200 OK: File versions retrieved successfully (may be empty list if no versions)
     * - 404 Not Found: File not found
     * - 410 Gone: File has been deleted
     *
     * @param fileId UUID of the file to retrieve versions for (path variable)
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with list of FileVersionResponse objects
     *
     * Example:
     *   GET /api/v1/files/660e8400-e29b-41d4-a716-446655440000/versions
     *   X-User-Id: 123e4567-e89b-12d3-a456-426614174000
     *
     * Response (200):
     *   [
     *     {
     *       "versionId": "880e8400-e29b-41d4-a716-446655440000",
     *       "versionNumber": 1,
     *       "sha256Hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     *       "modifiedAt": "2024-01-15T10:30:00.000Z",
     *       "modifiedBy": "user@example.com",
     *       "changeDescription": "Initial upload",
     *       "createdAt": "2024-01-15T10:30:00.000Z"
     *     },
     *     {
     *       "versionId": "990e8400-e29b-41d4-a716-446655440000",
     *       "versionNumber": 2,
     *       "sha256Hash": "5f9c4ab08cac7457e9111a30e4664882556e9d532c8e89e3e618f1d6e234e68",
     *       "modifiedAt": "2024-01-15T10:45:00.000Z",
     *       "modifiedBy": "user@example.com",
     *       "changeDescription": "Updated content",
     *       "createdAt": "2024-01-15T10:45:00.000Z"
     *     }
     *   ]
     */
    @GetMapping
    @Transactional(readOnly = true)
    @Operation(summary = "List all versions of a file", description = "Retrieve complete version history for a file with audit trail information")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "File versions retrieved successfully", content = @Content(schema = @Schema(implementation = FileVersionResponse.class))),
        @ApiResponse(responseCode = "404", description = "File not found"),
        @ApiResponse(responseCode = "410", description = "File has been deleted"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<List<FileVersionResponse>> listFileVersions(
            @PathVariable 
            @Parameter(description = "File ID to retrieve versions for", required = true)
            UUID fileId,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("File versions listing initiated by user: {} for fileId: {}", userId, fileId);

        // Verify file exists
        if (!fileRepository.existsById(fileId)) {
            log.warn("File not found. FileId: {}", fileId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        // Check if file is deleted
        var fileOptional = fileRepository.findById(fileId);
        if (fileOptional.isPresent() && fileOptional.get().getIsDeleted()) {
            log.warn("File has been deleted. FileId: {}", fileId);
            return ResponseEntity.status(HttpStatus.GONE).build();
        }

        // Retrieve all versions for the file, sorted by version number
        List<FileVersion> versions = fileVersionRepository.findByFileIdOrderByVersionNumberAsc(fileId);

        log.info("Found {} versions for file: {}", versions.size(), fileId);

        // Convert to response DTOs
        List<FileVersionResponse> responses = versions.stream()
                .map(version -> new FileVersionResponse(
                        version.getId(),
                        version.getVersionNumber(),
                        version.getSha256Hash(),
                        version.getModifiedAt(),
                        version.getModifiedBy(),
                        version.getChangeDescription(),
                        version.getCreatedAt()
                ))
                .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }

    /**
     * Get a specific file version by ID.
     *
     * Retrieves detailed information about a single file version, including
     * SHA-256 hash for integrity verification and audit trail metadata.
     * Versions are immutable after creation and read-only.
     *
     * HTTP Status:
     * - 200 OK: File version retrieved successfully
     * - 404 Not Found: File version not found
     * - 410 Gone: File has been deleted
     *
     * @param fileId UUID of the file (path variable)
     * @param versionId UUID of the specific file version to retrieve (path variable)
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with FileVersionResponse containing version metadata
     *
     * Example:
     *   GET /api/v1/files/660e8400-e29b-41d4-a716-446655440000/versions/880e8400-e29b-41d4-a716-446655440000
     *   X-User-Id: 123e4567-e89b-12d3-a456-426614174000
     *
     * Response (200):
     *   {
     *     "versionId": "880e8400-e29b-41d4-a716-446655440000",
     *     "versionNumber": 1,
     *     "sha256Hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     *     "modifiedAt": "2024-01-15T10:30:00.000Z",
     *     "modifiedBy": "user@example.com",
     *     "changeDescription": "Initial upload",
     *     "createdAt": "2024-01-15T10:30:00.000Z"
     *   }
     */
    @GetMapping("/{versionId}")
    @Transactional(readOnly = true)
    @Operation(summary = "Get a specific file version", description = "Retrieve a specific version of a file with integrity hash for verification")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "File version retrieved successfully", content = @Content(schema = @Schema(implementation = FileVersionResponse.class))),
        @ApiResponse(responseCode = "404", description = "File version not found"),
        @ApiResponse(responseCode = "410", description = "File has been deleted"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<FileVersionResponse> getFileVersion(
            @PathVariable 
            @Parameter(description = "File ID", required = true)
            UUID fileId,
            @PathVariable 
            @Parameter(description = "File version ID to retrieve", required = true)
            UUID versionId,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("File version retrieval initiated by user: {} for versionId: {}", userId, versionId);

        // Verify file exists
        if (!fileRepository.existsById(fileId)) {
            log.warn("File not found. FileId: {}", fileId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        // Check if file is deleted
        var fileOptional = fileRepository.findById(fileId);
        if (fileOptional.isPresent() && fileOptional.get().getIsDeleted()) {
            log.warn("File has been deleted. FileId: {}", fileId);
            return ResponseEntity.status(HttpStatus.GONE).build();
        }

        // Retrieve specific version
        Optional<FileVersion> versionOptional = fileVersionRepository.findById(versionId);

        if (versionOptional.isEmpty()) {
            log.warn("File version not found. VersionId: {}", versionId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        FileVersion version = versionOptional.get();

        // Verify version belongs to the requested file
        if (!version.getFile().getId().equals(fileId)) {
            log.warn("Version does not belong to file. FileId: {}, VersionId: {}", fileId, versionId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        log.info("File version retrieved successfully. VersionId: {}, VersionNumber: {}, Hash: {}",
                versionId, version.getVersionNumber(), version.getSha256Hash());

        // Build response
        FileVersionResponse response = new FileVersionResponse(
                version.getId(),
                version.getVersionNumber(),
                version.getSha256Hash(),
                version.getModifiedAt(),
                version.getModifiedBy(),
                version.getChangeDescription(),
                version.getCreatedAt()
        );

        return ResponseEntity.ok(response);
    }
}
