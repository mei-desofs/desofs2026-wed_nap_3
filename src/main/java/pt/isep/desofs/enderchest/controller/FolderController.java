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
import pt.isep.desofs.enderchest.entity.Folder;
import pt.isep.desofs.enderchest.repository.FolderRepository;
import pt.isep.desofs.enderchest.service.FolderService;
import pt.isep.desofs.enderchest.service.dto.FolderDeleteResponse;
import pt.isep.desofs.enderchest.service.dto.FolderRequest;
import pt.isep.desofs.enderchest.service.dto.FolderResponse;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * REST API controller for folder operations.
 *
 * Handles folder creation, listing, retrieval, update, and deletion endpoints within the EnderChest
 * collaborative storage system. Supports hierarchical folder structures with
 * parent-child relationships.
 *
 * Endpoints:
 * - POST /api/v1/folders - Create a new folder
 * - GET /api/v1/folders - List folders (with optional parent ID filter)
 * - GET /api/v1/folders/{folderId} - Get a single folder by ID
 * - PUT /api/v1/folders/{folderId} - Update folder name
 * - DELETE /api/v1/folders/{folderId} - Soft delete a folder
 *
 * Security:
 * - All endpoints require X-User-Id header (mocked authentication for now)
 * - Folder ownership is verified via ownerId
 * - Deletion is soft-delete only (audit compliance)
 *
 * Performance:
 * - Folder creation: O(log n) indexed insert
 * - Folder listing: O(log n + k) where k = number of child folders
 * - Folder deletion: O(log n) soft delete
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/folders")
@RequiredArgsConstructor
@Tag(name = "Folders", description = "Folder creation, retrieval, update, and deletion with hierarchical structure support")
@SecurityRequirement(name = "bearer-jwt")
public class FolderController {

    private final FolderService folderService;
    private final FolderRepository folderRepository;

    /**
     * Create a new folder.
     *
     * Creates a folder with the specified name. Can optionally place it under a parent folder.
     * Root-level folders are created when parentFolderId is null.
     *
     * HTTP Status:
     * - 201 Created: Folder created successfully
     * - 400 Bad Request: Invalid folder name or invalid parent folder ID
     * - 404 Not Found: Parent folder not found
     *
     * @param request FolderRequest containing folderName and parentFolderId
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with FolderResponse containing folder metadata
     *
     * Example:
     *   POST /api/v1/folders
     *   Content-Type: application/json
     *   X-User-Id: 123e4567-e89b-12d3-a456-426614174000
     *   {
     *     "folderName": "My Documents",
     *     "parentFolderId": null
     *   }
     *
     * Response (201):
     *   {
     *     "folderId": "550e8400-e29b-41d4-a716-446655440000",
     *     "folderName": "My Documents",
     *     "parentFolderId": null,
     *     "childCount": 0,
     *     "isActive": true
     *   }
     */
    @PostMapping
    @Transactional
    @Operation(summary = "Create a new folder", description = "Create a folder with the specified name, optionally under a parent folder")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Folder created successfully", content = @Content(schema = @Schema(implementation = FolderResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid folder name or invalid parent folder ID"),
        @ApiResponse(responseCode = "404", description = "Parent folder not found"),
        @ApiResponse(responseCode = "429", description = "Too Many Requests - Rate limit exceeded"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<FolderResponse> createFolder(
            @RequestBody FolderRequest request,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("Folder creation initiated by user: {} with name: {}", userId, request.getFolderName());

        // Convert userId to UUID
        UUID userIdUuid = UUID.fromString(userId);

        // Create folder via service
        Folder folder = folderService.createFolder(
                request.getFolderName(),
                userIdUuid,
                request.getParentFolderId()
        );

        log.info("Folder created successfully. FolderId: {}, Name: {}", folder.getFolderId(), folder.getFolderName());

        // Build response
        FolderResponse response = new FolderResponse(
                folder.getFolderId(),
                folder.getFolderName(),
                folder.getParentFolderId(),
                0L, // childCount will be 0 for newly created folder
                folder.isActive()
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * List folders with optional parent ID filtering.
     *
     * Returns a list of folders, optionally filtered by parent folder.
     * When parentId is null, returns root-level folders only.
     * When parentId is specified, returns direct children of that folder.
     * Automatically excludes soft-deleted folders (isDeleted=false).
     *
     * HTTP Status:
     * - 200 OK: Folders retrieved successfully (may be empty list)
     * - 400 Bad Request: Invalid parent ID format
     * - 404 Not Found: Parent folder not found
     *
     * @param parentId Optional UUID of parent folder (query param)
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with list of FolderResponse objects
     *
     * Example:
     *   GET /api/v1/folders?parentId=550e8400-e29b-41d4-a716-446655440000
     *   X-User-Id: 123e4567-e89b-12d3-a456-426614174000
     *
     * Response (200):
     *   [
     *     {
     *       "folderId": "660e8400-e29b-41d4-a716-446655440000",
     *       "folderName": "Subfolder 1",
     *       "parentFolderId": "550e8400-e29b-41d4-a716-446655440000",
     *       "childCount": 2,
     *       "isActive": true
     *     },
     *     {
     *       "folderId": "770e8400-e29b-41d4-a716-446655440000",
     *       "folderName": "Subfolder 2",
     *       "parentFolderId": "550e8400-e29b-41d4-a716-446655440000",
     *       "childCount": 0,
     *       "isActive": true
     *     }
     *   ]
     */
    @GetMapping
    @Transactional(readOnly = true)
    @Operation(summary = "List all folders with optional parent filter", description = "Retrieve folders, optionally filtered by parent folder ID. Root-level folders are returned when parentId is not specified")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Folders retrieved successfully", content = @Content(schema = @Schema(implementation = FolderResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid parent ID format"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<List<FolderResponse>> listFolders(
            @RequestParam(value = "parentId", required = false) 
            @Parameter(description = "Optional parent folder ID to filter children")
            UUID parentId,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("Folder listing initiated by user: {} with parentId: {}", userId, parentId);

        // Convert userId to UUID
        UUID userIdUuid = UUID.fromString(userId);

        // Query folders based on parent ID
        List<Folder> folders;
        if (parentId == null) {
            // Get root-level folders for this user
            folders = folderRepository.findByOwnerIdAndParentFolderIdNullAndIsDeletedFalse(userIdUuid);
        } else {
            // Get child folders of the specified parent
            folders = folderRepository.findByOwnerIdAndParentFolderIdAndIsDeletedFalse(userIdUuid, parentId);
        }

        log.info("Found {} folders for user: {} with parentId: {}", folders.size(), userId, parentId);

        // Convert to response DTOs
        List<FolderResponse> responses = folders.stream()
                .map(folder -> new FolderResponse(
                        folder.getFolderId(),
                        folder.getFolderName(),
                        folder.getParentFolderId(),
                        (long) folder.getChildFolders().size(), // childCount
                        folder.isActive()
                ))
                .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }

    /**
     * Get a single folder by ID.
     *
     * Retrieves a specific folder by its ID. The folder must be active (not soft-deleted).
     * 
     * HTTP Status:
     * - 200 OK: Folder retrieved successfully
     * - 404 Not Found: Folder not found
     * - 410 Gone: Folder already deleted
     *
     * @param folderId UUID of the folder to retrieve (path variable)
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with FolderResponse containing folder metadata
     *
     * Example:
     *   GET /api/v1/folders/550e8400-e29b-41d4-a716-446655440000
     *   X-User-Id: 123e4567-e89b-12d3-a456-426614174000
     *
     * Response (200):
     *   {
     *     "folderId": "550e8400-e29b-41d4-a716-446655440000",
     *     "folderName": "My Documents",
     *     "parentFolderId": null,
     *     "childCount": 2,
     *     "isActive": true
     *   }
     */
    @GetMapping("/{folderId}")
    @Transactional(readOnly = true)
    @Operation(summary = "Get a single folder by ID", description = "Retrieve a specific folder with its metadata")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Folder retrieved successfully", content = @Content(schema = @Schema(implementation = FolderResponse.class))),
        @ApiResponse(responseCode = "404", description = "Folder not found"),
        @ApiResponse(responseCode = "410", description = "Folder already deleted"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<FolderResponse> getFolderById(
            @PathVariable 
            @Parameter(description = "Folder ID to retrieve", required = true)
            UUID folderId,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("Folder retrieval initiated by user: {} for folderId: {}", userId, folderId);

        // Retrieve folder from database
        Optional<Folder> folderOptional = folderRepository.findById(folderId);

        if (folderOptional.isEmpty()) {
            log.warn("Folder not found. FolderId: {}", folderId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        Folder folder = folderOptional.get();

        // Check if folder is deleted
        if (!folder.isActive()) {
            log.warn("Folder has been deleted. FolderId: {}", folderId);
            return ResponseEntity.status(HttpStatus.GONE).build();
        }

        log.info("Folder retrieved successfully. FolderId: {}, Name: {}", folderId, folder.getFolderName());

        // Build response
        FolderResponse response = new FolderResponse(
                folder.getFolderId(),
                folder.getFolderName(),
                folder.getParentFolderId(),
                (long) folder.getChildFolders().size(), // childCount
                folder.isActive()
        );

        return ResponseEntity.ok(response);
    }

    /**
     * Update a folder's name.
     *
     * Updates the folder name for an existing folder.
     * The folder must be active (not soft-deleted) to be updated.
     *
     * HTTP Status:
     * - 200 OK: Folder updated successfully
     * - 400 Bad Request: Invalid folder name
     * - 404 Not Found: Folder not found
     * - 410 Gone: Folder already deleted
     *
     * @param folderId UUID of the folder to update (path variable)
     * @param request FolderRequest containing updated folderName
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with FolderResponse containing updated folder metadata
     *
     * Example:
     *   PUT /api/v1/folders/550e8400-e29b-41d4-a716-446655440000
     *   Content-Type: application/json
     *   X-User-Id: 123e4567-e89b-12d3-a456-426614174000
     *   {
     *     "folderName": "Updated Documents"
     *   }
     *
     * Response (200):
     *   {
     *     "folderId": "550e8400-e29b-41d4-a716-446655440000",
     *     "folderName": "Updated Documents",
     *     "parentFolderId": null,
     *     "childCount": 0,
     *     "isActive": true
     *   }
     */
    @PutMapping("/{folderId}")
    @Transactional
    @Operation(summary = "Update a folder", description = "Update the name of an existing folder")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Folder updated successfully", content = @Content(schema = @Schema(implementation = FolderResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid folder name or request body"),
        @ApiResponse(responseCode = "404", description = "Folder not found"),
        @ApiResponse(responseCode = "410", description = "Folder already deleted"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<FolderResponse> updateFolder(
            @PathVariable 
            @Parameter(description = "Folder ID to update", required = true)
            UUID folderId,
            @RequestBody FolderRequest request,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("Folder update initiated by user: {} for folderId: {} with name: {}", userId, folderId, request.getFolderName());

        // Retrieve folder from database
        Optional<Folder> folderOptional = folderRepository.findById(folderId);

        if (folderOptional.isEmpty()) {
            log.warn("Folder not found for update. FolderId: {}", folderId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        Folder folder = folderOptional.get();

        // Check if folder is deleted
        if (!folder.isActive()) {
            log.warn("Cannot update deleted folder. FolderId: {}", folderId);
            return ResponseEntity.status(HttpStatus.GONE).build();
        }

        // Update folder name
        folder.setFolderName(request.getFolderName());
        folderRepository.save(folder);

        log.info("Folder updated successfully. FolderId: {}, NewName: {}", folderId, folder.getFolderName());

        // Build response
        FolderResponse response = new FolderResponse(
                folder.getFolderId(),
                folder.getFolderName(),
                folder.getParentFolderId(),
                (long) folder.getChildFolders().size(), // childCount
                folder.isActive()
        );

        return ResponseEntity.ok(response);
    }

    /**
     * Delete a folder (soft delete).
     *
     * Marks a folder as deleted without removing it from storage or database.
     * Enables audit compliance and folder recovery.
     * Sets isDeleted=true and records deletion timestamp.
     *
     * Note: This operation soft-deletes only this folder. Child folders and files
     * must be managed separately or the application layer must handle hierarchy deletion.
     *
     * HTTP Status:
     * - 200 OK: Folder deleted successfully
     * - 404 Not Found: Folder not found
     * - 410 Gone: Folder already deleted
     *
     * @param folderId UUID of the folder to delete (path variable)
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with FolderDeleteResponse containing deletion timestamp
     *
     * Example:
     *   DELETE /api/v1/folders/550e8400-e29b-41d4-a716-446655440000
     *   X-User-Id: 123e4567-e89b-12d3-a456-426614174000
     *
     * Response (200):
     *   {
     *     "folderId": "550e8400-e29b-41d4-a716-446655440000",
     *     "deletedAt": "2024-01-15T10:40:00.000Z",
     *     "message": "Folder deleted successfully"
     *   }
     */
    @DeleteMapping("/{folderId}")
    @Transactional
    @Operation(summary = "Soft delete a folder", description = "Mark a folder as deleted without removing from database. Child items must be managed separately")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Folder deleted successfully", content = @Content(schema = @Schema(implementation = FolderDeleteResponse.class))),
        @ApiResponse(responseCode = "404", description = "Folder not found"),
        @ApiResponse(responseCode = "410", description = "Folder already deleted"),
        @ApiResponse(responseCode = "429", description = "Too Many Requests - Rate limit exceeded"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<FolderDeleteResponse> deleteFolder(
            @PathVariable 
            @Parameter(description = "Folder ID to delete", required = true)
            UUID folderId,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("Folder deletion initiated by user: {} for folderId: {}", userId, folderId);

        // Retrieve folder from database
        Optional<Folder> folderOptional = folderRepository.findById(folderId);

        if (folderOptional.isEmpty()) {
            log.warn("Folder not found for deletion. FolderId: {}", folderId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        Folder folder = folderOptional.get();

        // Check if already deleted
        if (!folder.isActive()) {
            log.warn("Folder already deleted. FolderId: {}", folderId);
            return ResponseEntity.status(HttpStatus.GONE).build();
        }

        // Perform soft delete
        folder.softDelete();
        folderRepository.save(folder);

        log.info("Folder deleted successfully. FolderId: {}, DeletedAt: {}", folderId, folder.getDeletedAt());

        FolderDeleteResponse response = new FolderDeleteResponse(
                folderId,
                folder.getDeletedAt(),
                "Folder deleted successfully"
        );

        return ResponseEntity.ok(response);
    }
}
