package pt.isep.desofs.enderchest.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pt.isep.desofs.enderchest.entity.Folder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for Folder entity.
 *
 * Provides data access layer for folder management operations including hierarchical
 * queries, access control filtering, and soft-delete handling.
 *
 * All queries respect the soft-delete pattern (isDeleted = false) by default for
 * consistency with the audit compliance requirements.
 *
 * Performance considerations:
 * - Queries use indexed columns for O(log n) lookups
 * - Composite indexes optimize common query patterns
 * - Lazy loading on relationships prevents N+1 query problems
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Repository
public interface FolderRepository extends JpaRepository<Folder, UUID> {

    /**
     * Find all folders owned by a specific user (including soft-deleted folders).
     *
     * Used for administrative operations and audit queries where deleted folders
     * may need to be included.
     *
     * @param ownerId The UUID of the folder owner
     * @return List of folders owned by the user (may include soft-deleted folders)
     */
    List<Folder> findByOwnerId(UUID ownerId);

    /**
     * Find all active (not soft-deleted) folders owned by a specific user.
     *
     * Used for displaying user's folder structure and folder queries.
     * Query execution time: O(log n + k) where k is user's active folders.
     * Leverages composite index (owner_id, is_deleted).
     *
     * @param ownerId The UUID of the folder owner
     * @return List of active folders owned by the user
     */
    List<Folder> findByOwnerIdAndIsDeletedFalse(UUID ownerId);

    /**
     * Find all root-level active folders owned by a specific user.
     *
     * Used for listing root-level folders only (where parentFolderId is null).
     * Query execution time: O(log n + k) where k is user's root folders.
     *
     * @param ownerId The UUID of the folder owner
     * @return List of root-level active folders owned by the user
     */
    List<Folder> findByOwnerIdAndParentFolderIdNullAndIsDeletedFalse(UUID ownerId);

    /**
     * Find all child folders of a specific parent by owner and parentFolderId.
     *
     * Used for hierarchical folder navigation with owner filtering.
     * Query execution time: O(log n + k) where k is matching child folders.
     *
     * @param ownerId The UUID of the folder owner
     * @param parentFolderId The UUID of the parent folder
     * @return List of active child folders for the owner
     */
    List<Folder> findByOwnerIdAndParentFolderIdAndIsDeletedFalse(UUID ownerId, UUID parentFolderId);

    /**
     * Find all child folders within a specific parent folder (including soft-deleted).
     *
     * Used for hierarchical folder navigation and administrative operations.
     *
     * @param parentFolderId The UUID of the parent folder
     * @return List of child folders (may include soft-deleted folders)
     */
    List<Folder> findByParentFolderId(UUID parentFolderId);

    /**
     * Find all active child folders within a specific parent folder.
     *
     * Used for displaying subfolder structures in the UI and folder hierarchies.
     * Query execution time: O(log n + k) where k is parent's active child folders.
     * Leverages composite index (parent_folder_id, is_deleted).
     *
     * @param parentFolderId The UUID of the parent folder
     * @return List of active child folders
     */
    List<Folder> findByParentFolderIdAndIsDeletedFalse(UUID parentFolderId);

    /**
     * Find an active folder by ID and verify it hasn't been soft-deleted.
     *
     * Used for all read operations to ensure only active folders are accessed.
     * Automatically filters out soft-deleted folders (isDeleted = true).
     * Query execution time: O(log n) with primary key index.
     *
     * @param folderId The folder UUID
     * @return Optional containing the Folder if found and active, empty otherwise
     */
    Optional<Folder> findByFolderIdAndIsDeletedFalse(UUID folderId);
}
