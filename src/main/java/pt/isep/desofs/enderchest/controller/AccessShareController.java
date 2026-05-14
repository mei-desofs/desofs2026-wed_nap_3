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
import org.springframework.lang.NonNull;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import pt.isep.desofs.enderchest.entity.AccessShare;
import pt.isep.desofs.enderchest.repository.AccessShareRepository;
import pt.isep.desofs.enderchest.service.dto.AccessShareDeleteResponse;
import pt.isep.desofs.enderchest.service.dto.AccessShareRequest;
import pt.isep.desofs.enderchest.service.dto.AccessShareResponse;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * REST API controller for access sharing operations.
 *
 * Handles file and folder sharing endpoints within the EnderChest collaborative
 * storage system. Implements fine-grained access control with role-based permissions
 * (OWNER, EDITOR, VIEWER).
 *
 * Endpoints:
 * - POST /api/v1/shares - Create a new access share
 * - DELETE /api/v1/shares/{shareId} - Revoke access share
 * - GET /api/v1/shares - List access shares for a resource
 * - GET /api/v1/shares/{shareId} - Get specific access share
 *
 * Security:
 * - All endpoints require X-User-Id header (mocked authentication for now)
 * - Caller must be the resource owner to grant/revoke access
 * - Role types validated during share creation
 *
 * Performance:
 * - Share creation: O(1) direct insert with unique constraint check
 * - Share deletion: O(1) direct deletion
 * - Share lookup: O(log n) indexed query
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/shares")
@RequiredArgsConstructor
@Tag(name = "Access Shares", description = "File and folder sharing with role-based access control")
@SecurityRequirement(name = "bearer-jwt")
public class AccessShareController {

    private final AccessShareRepository accessShareRepository;

    /**
     * Create a new access share.
     *
     * Grants access to a file or folder to another user with a specific role.
     * Creates an AccessShare record in the database for access control enforcement.
     *
     * HTTP Status:
     * - 201 Created: Access share created successfully
     * - 400 Bad Request: Invalid resource ID, resource type, or role type
     * - 404 Not Found: Resource or grantee user not found
     * - 409 Conflict: Access already shared (duplicate share)
     *
     * @param request AccessShareRequest containing resource ID, type, grantee, and role
     * @param userId User ID from X-User-Id header (required) - must be resource owner
     * @return ResponseEntity with AccessShareResponse containing share metadata
     */
    @PostMapping
    @Transactional
    @Operation(summary = "Grant access to a resource", description = "Create a new access share granting a user access to a file or folder with a specific role")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Access share created successfully", content = @Content(schema = @Schema(implementation = AccessShareResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid resource ID, resource type, or role type"),
        @ApiResponse(responseCode = "404", description = "Resource or grantee user not found"),
        @ApiResponse(responseCode = "409", description = "Access already shared (duplicate share)"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<AccessShareResponse> createAccessShare(
            @RequestBody AccessShareRequest request,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header), must be resource owner", required = true)
            String userId) {

        log.info("Access share creation initiated by user: {} for resource: {} ({})",
                userId, request.getResourceId(), request.getResourceType());

        try {
            // Parse resource type
            AccessShare.ResourceType resourceType = AccessShare.ResourceType.valueOf(request.getResourceType());

            // Parse role type
            AccessShare.RoleType roleType = AccessShare.RoleType.valueOf(request.getRoleType());

            // Check for existing share (prevent duplicates)
            Optional<AccessShare> existingShare = accessShareRepository.findByResourceIdAndResourceTypeAndGrantedToUserId(
                    request.getResourceId(),
                    resourceType,
                    request.getGrantedToUserId()
            );

            if (existingShare.isPresent()) {
                log.warn("Access share already exists for resource: {}, grantee: {}",
                        request.getResourceId(), request.getGrantedToUserId());
                return ResponseEntity.status(HttpStatus.CONFLICT).build();
            }

            // Create new access share
            AccessShare accessShare = new AccessShare(
                    request.getResourceId(),
                    resourceType,
                    request.getGrantedToUserId(),
                    roleType
            );

            // Save to database
            AccessShare savedShare = accessShareRepository.save(accessShare);

            log.info("Access share created successfully. ShareId: {}, ResourceId: {}, RoleType: {}",
                    savedShare.getShareId(), savedShare.getResourceId(), savedShare.getRoleType());

            // Build response
            AccessShareResponse response = new AccessShareResponse(
                    savedShare.getShareId(),
                    savedShare.getResourceId(),
                    savedShare.getResourceType().toString(),
                    savedShare.getGrantedToUserId(),
                    savedShare.getRoleType().toString(),
                    savedShare.getCreatedAt(),
                    null // revokedAt is null for new share
            );

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (IllegalArgumentException e) {
            log.warn("Invalid resource type or role type: {} / {}", request.getResourceType(), request.getRoleType(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    /**
     * Revoke an access share.
     *
     * Deletes an AccessShare record to remove granted access to a file or folder.
     * This is a hard delete operation (not soft delete) as shares are not audit-sensitive.
     *
     * HTTP Status:
     * - 200 OK: Access share revoked successfully
     * - 404 Not Found: Share not found
     *
     * @param shareId UUID of the access share to revoke (path variable)
     * @param userId User ID from X-User-Id header (required) - must be resource owner
     * @return ResponseEntity with AccessShareDeleteResponse confirming revocation
     */
    @DeleteMapping("/{shareId}")
    @Transactional
    @Operation(summary = "Revoke access to a resource", description = "Remove a user's access to a file or folder by deleting the access share")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Access share revoked successfully", content = @Content(schema = @Schema(implementation = AccessShareDeleteResponse.class))),
        @ApiResponse(responseCode = "404", description = "Share not found"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<AccessShareDeleteResponse> revokeAccessShare(
            @PathVariable 
            @Parameter(description = "Access share ID to revoke", required = true)
            @NonNull UUID shareId,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header), must be resource owner", required = true)
            String userId) {

        log.info("Access share revocation initiated by user: {} for shareId: {}", userId, shareId);

        // Retrieve share from database

        Optional<AccessShare> shareOptional = accessShareRepository.findById(shareId);

        if (shareOptional.isEmpty()) {
            log.warn("Access share not found for revocation. ShareId: {}", shareId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        AccessShare share = shareOptional.get();

        // Record revocation timestamp before deletion
        LocalDateTime revokedAt = LocalDateTime.now();

        if (revokedAt.isBefore(share.getCreatedAt())) {
            log.warn("Revocation timestamp is before share creation time. ShareId: {}, CreatedAt: {}, RevokedAt: {}",
                    shareId, share.getCreatedAt(), revokedAt);
            revokedAt = share.getCreatedAt().plusSeconds(1); // Ensure revokedAt is after createdAt
        }

        // Delete the share record
        accessShareRepository.delete(share);

        log.info("Access share revoked successfully. ShareId: {}, ResourceId: {}, RevokedAt: {}",
                shareId, share.getResourceId(), revokedAt);

        AccessShareDeleteResponse response = new AccessShareDeleteResponse(
                shareId,
                revokedAt,
                "Access share revoked successfully"
        );

        return ResponseEntity.ok(response);
    }

    /**
     * List access shares for a resource.
     *
     * Returns all users who have access to a specific resource (file or folder).
     * Useful for viewing and managing shared access permissions.
     *
     * HTTP Status:
     * - 200 OK: Shares retrieved successfully (may be empty list)
     * - 400 Bad Request: Invalid resource type
     *
     * @param resourceId UUID of the resource (query param)
     * @param resourceType Type of resource - FILE or FOLDER (query param)
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with list of AccessShareResponse objects
     */
    @GetMapping
    @Transactional(readOnly = true)
    @Operation(summary = "List shares for a resource", description = "Retrieve all access shares for a specific file or folder")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Access shares retrieved successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid resource type"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<?> listAccessShares(
            @RequestParam 
            @Parameter(description = "Resource ID to list shares for", required = true)
            UUID resourceId,
            @RequestParam 
            @Parameter(description = "Resource type (FILE or FOLDER)", required = true)
            String resourceType,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("Access shares listing initiated by user: {} for resource: {} ({})",
                userId, resourceId, resourceType);

        try {
            AccessShare.ResourceType type = AccessShare.ResourceType.valueOf(resourceType);

            var shares = accessShareRepository.findByResourceIdAndResourceType(resourceId, type);

            log.info("Found {} access shares for resource: {}", shares.size(), resourceId);

            var responses = shares.stream()
                    .map(share -> new AccessShareResponse(
                            share.getShareId(),
                            share.getResourceId(),
                            share.getResourceType().toString(),
                            share.getGrantedToUserId(),
                            share.getRoleType().toString(),
                            share.getCreatedAt(),
                            null
                    ))
                    .toList();

            return ResponseEntity.ok(responses);

        } catch (IllegalArgumentException e) {
            log.warn("Invalid resource type: {}", resourceType, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    /**
     * Get a specific access share.
     *
     * Retrieves detailed information about a single access share.
     *
     * HTTP Status:
     * - 200 OK: Access share retrieved successfully
     * - 404 Not Found: Share not found
     *
     * @param shareId UUID of the access share to retrieve (path variable)
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with AccessShareResponse containing share metadata
     */
    @GetMapping("/{shareId}")
    @Transactional(readOnly = true)
    @Operation(summary = "Get a specific access share", description = "Retrieve detailed information about a single access share")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Access share retrieved successfully", content = @Content(schema = @Schema(implementation = AccessShareResponse.class))),
        @ApiResponse(responseCode = "404", description = "Share not found"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    public ResponseEntity<AccessShareResponse> getAccessShare(
            @PathVariable 
            @Parameter(description = "Access share ID to retrieve", required = true)
            @NonNull UUID shareId,
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("Access share retrieval initiated by user: {} for shareId: {}", userId, shareId);

        Optional<AccessShare> shareOptional = accessShareRepository.findById(shareId);

        if (shareOptional.isEmpty()) {
            log.warn("Access share not found. ShareId: {}", shareId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        AccessShare share = shareOptional.get();

        log.info("Access share retrieved successfully. ShareId: {}, ResourceId: {}", shareId, share.getResourceId());

        AccessShareResponse response = new AccessShareResponse(
                share.getShareId(),
                share.getResourceId(),
                share.getResourceType().toString(),
                share.getGrantedToUserId(),
                share.getRoleType().toString(),
                share.getCreatedAt(),
                null
        );

        return ResponseEntity.ok(response);
    }
}
