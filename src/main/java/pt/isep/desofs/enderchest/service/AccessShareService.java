package pt.isep.desofs.enderchest.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pt.isep.desofs.enderchest.entity.AccessShare;
import pt.isep.desofs.enderchest.exception.resource.AccessShareNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.DuplicateAccessShareException;
import pt.isep.desofs.enderchest.repository.AccessShareRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Service layer for access share management operations.
 *
 * This service provides business logic for:
 * - Creating access shares (granting access to resources)
 * - Revoking access shares (removing access from resources)
 * - Listing access shares for a resource
 * - Retrieving specific access share details
 *
 * Design Principles:
 * - Duplicate prevention: Checks for existing shares before creation
 * - Transactional: All write operations are atomic
 * - Performance-optimized: Uses repository indexes for efficient queries
 * - Audit-compliant: Logs all access control operations
 *
 * Performance Characteristics:
 * - createAccessShare: O(log n) - indexed lookup + O(1) insert
 * - revokeAccessShare: O(log n) - indexed deletion
 * - listAccessSharesByResourceId: O(log n + k) where k = number of shares
 * - getAccessShareById: O(log n) - primary key lookup
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AccessShareService {

    private final AccessShareRepository accessShareRepository;

    /**
     * Create a new access share.
     *
     * Grants access to a file or folder to another user with a specific role.
     * Prevents duplicate shares for the same resource and user.
     *
     * @param resourceId UUID of the resource (file or folder)
     * @param resourceType Type of resource (FILE or FOLDER)
     * @param grantedToUserId UUID of the user granted access
     * @param role Role level to grant (OWNER, EDITOR, VIEWER)
     * @return Created AccessShare entity
     * @throws DuplicateAccessShareException if share already exists
     */
    @Transactional
    @NonNull
    public AccessShare createAccessShare(@NonNull UUID resourceId, @NonNull AccessShare.ResourceType resourceType,
                                         @NonNull UUID grantedToUserId, @NonNull AccessShare.RoleType role)
            throws DuplicateAccessShareException {

        // Check for existing share (prevent duplicates)
        Optional<AccessShare> existingShare = accessShareRepository
                .findByResourceIdAndResourceTypeAndGrantedToUserId(resourceId, resourceType, grantedToUserId);

        if (existingShare.isPresent()) {
            log.warn("Access share already exists for resource: {}, grantee: {}",
                    resourceId, grantedToUserId);
            throw new DuplicateAccessShareException(resourceId, grantedToUserId);
        }

        // Create new access share
        AccessShare accessShare = new AccessShare(resourceId, resourceType, grantedToUserId, role);

        // Save to database
        AccessShare savedShare = accessShareRepository.save(accessShare);

        log.info("Access share created successfully. ShareId: {}, ResourceId: {}, RoleType: {}",
                savedShare.getShareId(), savedShare.getResourceId(), savedShare.getRoleType());

        return savedShare;
    }

    /**
     * Revoke an access share.
     *
     * Deletes an AccessShare record to remove granted access to a resource.
     *
     * @param shareId UUID of the access share to revoke
     * @throws AccessShareNotFoundException if share not found
     */
    @Transactional
    public void revokeAccessShare(@NonNull UUID shareId) throws AccessShareNotFoundException {

        // Retrieve share from database
        Optional<AccessShare> shareOptional = accessShareRepository.findById(shareId);

        if (shareOptional.isEmpty()) {
            log.warn("Access share not found for revocation. ShareId: {}", shareId);
            throw new AccessShareNotFoundException(shareId);
        }

        AccessShare share = shareOptional.get();

        // Delete the share record
        accessShareRepository.delete(share);

        log.info("Access share revoked successfully. ShareId: {}, ResourceId: {}",
                shareId, share.getResourceId());
    }

    /**
     * List all access shares for a specific resource.
     *
     * Returns all users who have access to a resource (file or folder).
     *
     * @param resourceId UUID of the resource
     * @param resourceType Type of resource (FILE or FOLDER)
     * @return List of AccessShare entities for the resource (may be empty)
     */
    @Transactional(readOnly = true)
    @NonNull
    public List<AccessShare> listAccessSharesByResourceId(@NonNull UUID resourceId, @NonNull AccessShare.ResourceType resourceType) {

        List<AccessShare> shares = accessShareRepository
                .findByResourceIdAndResourceType(resourceId, resourceType);

        log.info("Found {} access shares for resource: {}", shares.size(), resourceId);

        return shares;
    }

    /**
     * Retrieve a specific access share by ID.
     *
     * @param shareId UUID of the access share
     * @return AccessShare entity
     * @throws AccessShareNotFoundException if share not found
     */
    @Transactional(readOnly = true)
    @NonNull
    public AccessShare getAccessShareById(@NonNull UUID shareId) throws AccessShareNotFoundException {

        Optional<AccessShare> shareOptional = accessShareRepository.findById(shareId);

        if (shareOptional.isEmpty()) {
            log.warn("Access share not found. ShareId: {}", shareId);
            throw new AccessShareNotFoundException(shareId);
        }

        AccessShare share = shareOptional.get();

        log.info("Access share retrieved successfully. ShareId: {}, ResourceId: {}",
                shareId, share.getResourceId());

        return share;
    }
}
