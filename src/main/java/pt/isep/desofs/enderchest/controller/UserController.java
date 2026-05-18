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
import pt.isep.desofs.enderchest.exception.resource.UserNotFoundException;
import pt.isep.desofs.enderchest.service.UserService;
import pt.isep.desofs.enderchest.service.dto.UserProfileResponse;

import java.util.UUID;

/**
 * REST API controller for user profile operations.
 *
 * Thin HTTP layer that delegates all business logic to UserService.
 * Handles user profile endpoint within the EnderChest collaborative storage system.
 * Provides access to user identity and storage quota information.
 *
 * Endpoints:
 * - GET /api/v1/users/me - Get authenticated user's profile
 * - HEAD /api/v1/users/{userId} - Check if user exists
 *
 * Security:
 * - All endpoints require X-User-Id header (mocked authentication for now)
 * - Users can only access their own profile information
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Tag(name = "Users", description = "User profile and storage quota operations")
@SecurityRequirement(name = "bearer-jwt")
public class UserController {

    private final UserService userService;

    /**
     * Get authenticated user's profile.
     *
     * Returns the authenticated user's identity and storage quota information.
     * Delegates to UserService for profile retrieval and storage calculation.
     *
     * HTTP Status:
     * - 200 OK: User profile retrieved successfully
     * - 404 Not Found: User not found (should not happen for authenticated user)
     * - 400 Bad Request: Invalid user ID format
     *
     * @param userId User ID from X-User-Id header (required)
     * @return ResponseEntity with UserProfileResponse containing user profile data
     *
     * Example:
     *   GET /api/v1/users/me
     *   X-User-Id: 123e4567-e89b-12d3-a456-426614174000
     *
     * Response (200):
     *   {
     *     "userId": "123e4567-e89b-12d3-a456-426614174000",
     *     "username": "john.doe",
     *     "email": "john.doe@example.com",
     *     "fullName": "John Doe",
     *     "storageQuota": 10737418240,
     *     "usedStorage": 2147483648,
     *     "availableStorage": 8589934592
     *   }
     */
    @GetMapping("/me")
    @Transactional(readOnly = true)
    @Operation(summary = "Get authenticated user profile with storage quota", description = "Retrieve the authenticated user's profile information including storage quota, used storage, and available storage")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User profile retrieved successfully", content = @Content(schema = @Schema(implementation = UserProfileResponse.class))),
        @ApiResponse(responseCode = "404", description = "User not found"),
        @ApiResponse(responseCode = "400", description = "Invalid user ID format"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - missing or invalid bearer token")
    })
    @SuppressWarnings("null")
    public ResponseEntity<UserProfileResponse> getCurrentUserProfile(
            @RequestHeader(value = "X-User-Id", required = true) 
            @Parameter(description = "User ID (from authentication header)", required = true)
            String userId) {

        log.info("User profile request from user: {}", userId);

        try {
            // Convert userId string to UUID
            UUID userIdUuid = UUID.fromString(userId);

            // Delegate to UserService for profile retrieval
            UserProfileResponse response = userService.getUserProfile(userIdUuid);

            log.info("User profile retrieved. UserId: {}", userId);
            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            log.error("Invalid user ID format: {}", userId, e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (UserNotFoundException e) {
            log.warn("User not found. UserId: {}", userId, e);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    /**
     * Check if a user exists by ID.
     *
     * Helper endpoint to verify if a user is registered in the system.
     * Useful for access control verification.
     * Delegates to UserService for existence check.
     *
     * HTTP Status:
     * - 200 OK: User exists
     * - 404 Not Found: User does not exist
     *
     * @param userId User ID to check (path variable)
     * @return ResponseEntity with existence confirmation
     *
     * Example:
     *   HEAD /api/v1/users/{userId}
     *
     * Response (200): User exists
     * Response (404): User not found
     */
    @RequestMapping(value = "/{userId}", method = org.springframework.web.bind.annotation.RequestMethod.HEAD)
    @Transactional(readOnly = true)
    @Operation(summary = "Check if user exists", description = "Verify user existence by ID")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User exists"),
        @ApiResponse(responseCode = "404", description = "User not found")
    })
    @SuppressWarnings("null")
    public ResponseEntity<Void> checkUserExists(
            @PathVariable 
            @Parameter(description = "User ID to check", required = true)
            String userId) {

        try {
            UUID userIdUuid = UUID.fromString(userId);

            if (userService.checkUserExists(userIdUuid)) {
                log.debug("User exists. UserId: {}", userId);
                return ResponseEntity.ok().build();
            } else {
                log.debug("User not found. UserId: {}", userId);
                return ResponseEntity.notFound().build();
            }

        } catch (IllegalArgumentException e) {
            log.debug("Invalid user ID format: {}", userId);
            return ResponseEntity.notFound().build();
        }
    }
}
