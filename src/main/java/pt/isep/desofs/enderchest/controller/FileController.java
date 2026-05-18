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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.exception.resource.FileNotFoundException;
import pt.isep.desofs.enderchest.exception.security.FileAccessDeniedException;
import pt.isep.desofs.enderchest.service.FileService;
import pt.isep.desofs.enderchest.service.FileStorageService;
import pt.isep.desofs.enderchest.service.dto.FileDeleteResponse;
import pt.isep.desofs.enderchest.service.dto.UploadResponse;

import java.net.MalformedURLException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

/**
 * REST API controller for file operations.
 *
 * Handles file upload, download, and deletion endpoints within the EnderChest
 * collaborative storage system. Authentication is performed via JWT (Auth0).
 * Authorization is enforced via RBAC with @PreAuthorize (SDR-02).
 *
 * The userId is extracted from the JWT subject claim — never from client-supplied
 * headers. This prevents user impersonation attacks where a malicious client
 * could forge the X-User-Id header.
 *
 * Endpoints:
 * - POST /api/v1/files/upload       — Upload a file (OWNER, EDITOR)
 * - GET  /api/v1/files/{fileId}     — Download a file (OWNER, EDITOR, VIEWER)
 * - DELETE /api/v1/files/{fileId}   — Soft delete a file (OWNER only)
 * - GET  /api/v1/files/admin/health — Admin health check (ADMIN only) [ST-07]
 *
 * Security:
 * - All endpoints require a valid JWT in the Authorization header
 * - Roles are extracted from JWT claim: https://enderchest-api/roles
 * - userId is extracted from JWT subject (sub) claim — not from headers
 * - File ownership is verified before operations
 * - SHA-256 hash verification on download
 *
 * @author Developer 2 — Authorization Specialist
 * @version 1.1
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/files")
@RequiredArgsConstructor
@Tag(name = "Files", description = "File upload, download, and deletion operations")
@SecurityRequirement(name = "bearer-jwt")
public class FileController {

    private final FileStorageService fileStorageService;
    private final FileService fileService;

    /**
     * Upload a file to storage.
     * Only OWNER and EDITOR roles can upload files (SDR-02, T-09 mitigation).
     *
     * The userId is extracted from the JWT subject (sub) claim to prevent
     * header forgery attacks.
     *
     * Business logic delegated to FileStorageService.
     */
    @PostMapping("/upload")
    @Transactional
    @PreAuthorize("hasAuthority('ROLE_OWNER') or hasAuthority('ROLE_EDITOR')")
    @Operation(summary = "Upload a file", description = "Upload a new file with SHA-256 integrity verification, storage quota enforcement, and optional folder placement")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "File uploaded successfully", content = @Content(schema = @Schema(implementation = UploadResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid file or missing required fields"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token"),
            @ApiResponse(responseCode = "403", description = "Forbidden - insufficient role (VIEWER cannot upload)"),
            @ApiResponse(responseCode = "409", description = "File already exists (deduplication)"),
            @ApiResponse(responseCode = "413", description = "Payload Too Large - User storage quota exceeded"),
            @ApiResponse(responseCode = "415", description = "Unsupported Media Type - File type not allowed")
    })
    public ResponseEntity<UploadResponse> uploadFile(
            @RequestParam("file")
            @Parameter(description = "File to upload", required = true)
            MultipartFile file,
            @RequestParam(value = "folderId", required = false)
            @Parameter(description = "Optional parent folder ID")
            UUID folderId,
            @AuthenticationPrincipal Jwt jwt) {

        // Extract userId from JWT subject claim — never trust client-supplied headers
        String userId = jwt.getSubject();

        log.info("File upload initiated by user: {} for folder: {}", userId, folderId);

        UploadResponse response = fileStorageService.uploadFile(file, userId, folderId);

        log.info("File uploaded successfully. FileId: {}, Hash: {}, Size: {} bytes",
                response.getFileId(), response.getSha256Hash(), response.getFileSize());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Download a file by its ID.
     * OWNER, EDITOR and VIEWER can download files they have access to (SDR-02).
     *
     * Access control is delegated to FileService.downloadFile() which performs
     * IDOR prevention checks (AC-04 / ST-02) before returning the file.
     */
    @GetMapping("/{fileId}")
    @PreAuthorize("hasAuthority('ROLE_OWNER') or hasAuthority('ROLE_EDITOR') or hasAuthority('ROLE_VIEWER')")
    @Operation(summary = "Download a file", description = "Download a file by ID with SHA-256 integrity verification")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "File downloaded successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token"),
            @ApiResponse(responseCode = "403", description = "Forbidden - insufficient access to file"),
            @ApiResponse(responseCode = "404", description = "File not found or has been deleted"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @SuppressWarnings("null")
    public ResponseEntity<Resource> downloadFile(
            @PathVariable UUID fileId,
            @AuthenticationPrincipal Jwt jwt) {

        // Extract userId from JWT subject — never trust client-supplied headers
        String userId = jwt.getSubject();
        String email = jwt.getClaimAsString("email");

        log.info("File download initiated by user: {} for fileId: {}", userId, fileId);

        try {
            // Delegate to FileService for access control and file retrieval
            File file = fileService.downloadFile(fileId, userId, email);

            // Construct file path and load resource
            Path filePath = Paths.get(file.getStorageLocation());
            Resource resource = new UrlResource(filePath.toUri());

            if (!resource.exists()) {
                log.error("File resource not found in storage. FileId: {}, Path: {}", fileId, filePath);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }

            // Build HTTP response headers
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

        } catch (FileNotFoundException e) {
            log.warn("File not found: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (FileAccessDeniedException e) {
            log.warn("IDOR attempt blocked: user {} attempted to access file {} without permission", userId, fileId);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (MalformedURLException e) {
            log.error("Invalid file URL. FileId: {}", fileId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Delete a file (soft delete).
     * Only OWNER can delete files (SDR-02, T-09 mitigation — Editor cannot delete).
     *
     * Access control is delegated to FileService.deleteFile() which performs
     * IDOR prevention checks (AC-04 / ST-02) before deletion.
     */
    @DeleteMapping("/{fileId}")
    @PreAuthorize("hasAuthority('ROLE_OWNER')")
    @Operation(summary = "Soft delete a file", description = "Mark a file as deleted without removing from storage or database")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "File deleted successfully", content = @Content(schema = @Schema(implementation = FileDeleteResponse.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token"),
            @ApiResponse(responseCode = "403", description = "Forbidden - only OWNER can delete files"),
            @ApiResponse(responseCode = "404", description = "File not found or already deleted"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @SuppressWarnings("null")
    public ResponseEntity<FileDeleteResponse> deleteFile(
            @PathVariable
            @Parameter(description = "File ID to delete", required = true)
            UUID fileId,
            @AuthenticationPrincipal Jwt jwt) {

        // Extract userId from JWT subject — never trust client-supplied headers
        String userId = jwt.getSubject();
        String email = jwt.getClaimAsString("email");

        log.info("File deletion initiated by user: {} for fileId: {}", userId, fileId);

        try {
            // Delegate to FileService for access control and deletion
            // FileService.deleteFile() handles all access checks and performs the soft delete
            fileService.deleteFile(fileId, userId, email);

            // Build success response with current timestamp
            FileDeleteResponse response = new FileDeleteResponse(
                    fileId,
                    java.time.LocalDateTime.now(),
                    "File deleted successfully"
            );

            log.info("File deleted successfully. FileId: {}", fileId);
            return ResponseEntity.ok(response);

        } catch (FileNotFoundException e) {
            log.warn("File not found: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (FileAccessDeniedException e) {
            log.warn("IDOR attempt blocked: user {} attempted to delete file {} without ownership", userId, fileId);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    /**
     * Admin health check endpoint — ST-07 (Authorization Tests).
     *
     * Endpoint criado para demonstrar e testar RBAC:
     * - ADMIN: 200 OK
     * - OWNER, EDITOR, VIEWER: 403 Forbidden
     * - Não autenticado: 401 Unauthorized
     *
     * Mitiga: SDR-02 (RBAC), T-10 (Unauthorized Access to Admin Endpoints)
     */
    @GetMapping("/admin/health")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @Operation(summary = "Admin health check", description = "Administrative health check endpoint. Requires ADMIN role.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Admin health check OK"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token"),
            @ApiResponse(responseCode = "403", description = "Forbidden - requires ROLE_ADMIN")
    })
    public ResponseEntity<String> adminHealth() {
        return ResponseEntity.ok("Admin health check: OK");
    }
}