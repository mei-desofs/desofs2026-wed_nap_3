package pt.isep.desofs.enderchest.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;
import pt.isep.desofs.enderchest.entity.AccessShare;
import pt.isep.desofs.enderchest.entity.AccessShare.ResourceType;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for AccessShare entity.
 *
 * Provides data access layer for access control operations. Supports fine-grained
 * permission queries for determining what resources a user can access and what
 * permissions are granted to users for specific resources.
 *
 * Enables polymorphic resource sharing through (resourceId, resourceType) composite
 * identification, supporting both FILE and FOLDER resource types.
 *
 * Performance considerations:
 * - Queries leverage composite index (resource_id, resource_type, granted_to_user_id)
 * - Grantee lookup uses indexed column (granted_to_user_id)
 * - All queries are O(log n + k) where k is number of shares matching criteria
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Repository
public interface AccessShareRepository extends JpaRepository<AccessShare, UUID> {

    /**
     * Find all access shares for a specific resource.
     *
     * Used for determining who has access to a resource and what permissions they have.
     * Supports both FILE and FOLDER resource types.
     *
     * Query execution time: O(log n + k) where k is number of users with access.
     * Leverages composite index (resource_id, resource_type, granted_to_user_id).
     *
     * @param resourceId The UUID of the resource (file or folder)
     * @param resourceType The type of resource (FILE or FOLDER)
     * @return List of AccessShare records for the specified resource
     */
    @NonNull
    List<AccessShare> findByResourceIdAndResourceType(UUID resourceId, ResourceType resourceType);

    /**
     * Find all resources shared with a specific user.
     *
     * Used for displaying a user's shared resources and permission queries.
     * Returns all AccessShare records granted to a user regardless of resource type.
     *
     * Query execution time: O(log n + k) where k is number of shares for the user.
     * Leverages index on granted_to_user_id.
     *
     * @param grantedToUserId The UUID of the user who has been granted access
     * @return List of AccessShare records for the specified user
     */
    @NonNull
    List<AccessShare> findByGrantedToUserId(UUID grantedToUserId);

    /**
     * Find a specific access share by resource, resource type, and grantee.
     *
     * Used to check if access is already shared to prevent duplicate shares.
     * Query execution time: O(log n) with composite index.
     *
     * @param resourceId The UUID of the resource
     * @param resourceType The type of resource (FILE or FOLDER)
     * @param grantedToUserId The UUID of the user granted access
     * @return Optional containing the AccessShare if found, empty otherwise
     */
    @NonNull
    Optional<AccessShare> findByResourceIdAndResourceTypeAndGrantedToUserId(
            UUID resourceId,
            ResourceType resourceType,
            UUID grantedToUserId
    );
}
