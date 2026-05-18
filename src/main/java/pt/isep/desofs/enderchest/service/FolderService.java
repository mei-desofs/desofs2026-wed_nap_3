package pt.isep.desofs.enderchest.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pt.isep.desofs.enderchest.entity.Folder;
import pt.isep.desofs.enderchest.exception.resource.CircularReferenceFolderException;
import pt.isep.desofs.enderchest.exception.resource.FolderNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.InvalidFolderNameException;
import pt.isep.desofs.enderchest.repository.FolderRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Service layer for folder management operations.
 *
 * This service provides business logic for:
 * - Creating folders with hierarchical support (parent-child relationships)
 * - Retrieving folders with access control filtering
 * - Listing folder structures and hierarchies
 * - Soft-deleting folders while maintaining audit trails
 * - Managing nested folder hierarchies
 *
 * Design Principles:
 * - Soft delete only: Marked as isDeleted=true, never hard deleted from database
 * - No authorization checks: Assumes caller has verified permissions externally
 * - Transactional: All write operations are atomic
 * - Performance-optimized: Uses repository indexes for efficient queries
 * - Audit-compliant: Logs all folder operations for compliance
 *
 * Security Considerations:
 * - Authorization checks are external to this service (handled by controllers/interceptors)
 * - All queries filter out deleted folders (isDeleted=false) by default
 * - Folder hierarchy is validated implicitly through repository foreign keys
 * - UUID identifiers prevent sequential ID enumeration attacks
 *
 * Performance Characteristics:
 * - createFolder: O(log n) - indexed lookup + O(1) insert
 * - listFolders: O(log n + k) where k = number of child folders
 * - listAllUserFolders: O(log n + m) where m = number of user's folders
 * - getFolderById: O(log n) - primary key lookup
 * - softDeleteFolder: O(log n + c) where c = number of child folders (if recursive)
 * - hardDeleteFolder: O(log n) - direct deletion
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class FolderService {

    private final FolderRepository folderRepository;

    /**
     * Create a new folder in the file system.
     *
     * Creates a folder with the specified name under a parent folder, or at the root
     * level if parentFolderId is null. The folder is created with isDeleted=false
     * and is immediately queryable.
     *
     * Validation:
     * - folderName must not be null or blank (validated by entity @NotBlank)
     * - ownerId must not be null (validated by entity @NotNull)
     * - parentFolderId is optional (can be null for root folders)
     *
     * Performance: O(log n) for repository save operation
     * Database: Indexed insert via primary key generation
     *
     * @param folderName The name of the folder to create (required, non-blank)
     * @param ownerId The UUID of the folder owner (required)
     * @param parentFolderId The UUID of the parent folder, or null for root-level folders
     * @return The created Folder entity with generated folderId
     * @throws IllegalArgumentException if folderName is null or blank
     * @throws IllegalArgumentException if ownerId is null
     * @throws IllegalArgumentException if parentFolderId is not null and parent folder doesn't exist
     *
     * Example:
     *   // Create root folder
     *   Folder rootFolder = folderService.createFolder("Documents", userId, null);
     *
     *   // Create subfolder
     *   Folder subFolder = folderService.createFolder("Reports", userId, rootFolder.getFolderId());
     */
    @Transactional
    public Folder createFolder(String folderName, UUID ownerId, UUID parentFolderId) {
        // Input validation
        if (folderName == null || folderName.isBlank()) {
            throw new IllegalArgumentException("Folder name must not be null or blank");
        }

        if (ownerId == null) {
            throw new IllegalArgumentException("Owner ID must not be null");
        }

        // If parentFolderId is provided, verify parent folder exists and is not deleted
        if (parentFolderId != null) {
            Optional<Folder> parentFolder = folderRepository.findByFolderIdAndIsDeletedFalse(parentFolderId);
            if (parentFolder.isEmpty()) {
                throw new IllegalArgumentException(
                    String.format("Parent folder does not exist or has been deleted: %s", parentFolderId)
                );
            }
        }

        // Create new folder
        Folder folder = new Folder(folderName, ownerId, parentFolderId);

        // Save to database
        Folder createdFolder = folderRepository.save(folder);

        // Log folder creation (security audit)
        log.info("Folder created: folderId={}, folderName={}, ownerId={}, parentFolderId={}, isDeleted=false",
            createdFolder.getFolderId(), createdFolder.getFolderName(), ownerId, parentFolderId);

        return createdFolder;
    }

    /**
     * List all child folders within a parent folder.
     *
     * Returns all active (non-deleted) child folders of the specified parent.
     * If parentFolderId is null, returns root-level folders (folders with no parent).
     *
     * Performance: O(log n + k) where k = number of child folders
     * Uses composite index (parent_folder_id, is_deleted) for efficient query
     *
     * @param parentFolderId The UUID of the parent folder, or null to list root folders
     * @return List of active child Folder entities (may be empty if no children)
     *
     * Example:
     *   // List root folders
     *   List<Folder> rootFolders = folderService.listFolders(null);
     *
     *   // List subfolders of a parent
     *   List<Folder> subFolders = folderService.listFolders(parentFolderId);
     */
    @Transactional(readOnly = true)
    public List<Folder> listFolders(UUID parentFolderId) {
        if (parentFolderId == null) {
            // For root folders, we need to find folders where parentFolderId is null AND isDeleted is false
            // Since the repository doesn't have this exact method, we use a workaround:
            // We get all folders by owner, then filter by parentFolderId null in application memory
            // OR we query all folders and filter (less efficient but acceptable for root listing)
            
            // Better approach: Get all folders and filter in-memory (acceptable for small result sets)
            // For large result sets, a custom @Query would be better
            // For now, listing all and filtering is acceptable since root folders are typically few
            List<Folder> allFolders = folderRepository.findAll();
            return allFolders.stream()
                .filter(f -> !f.getIsDeleted() && f.getParentFolderId() == null)
                .toList();
        }

        // List child folders of a specific parent
        return folderRepository.findByParentFolderIdAndIsDeletedFalse(parentFolderId);
    }

    /**
     * List all folders owned by a specific user.
     *
     * Returns all active (non-deleted) folders owned by the specified user,
     * regardless of their position in the folder hierarchy.
     *
     * Performance: O(log n + m) where m = number of user's active folders
     * Uses composite index (owner_id, is_deleted) for efficient query
     *
     * @param ownerId The UUID of the folder owner
     * @return List of all active folders owned by the user (may be empty if user has no folders)
     *
     * Example:
     *   List<Folder> userFolders = folderService.listAllUserFolders(userId);
     */
    @Transactional(readOnly = true)
    public List<Folder> listAllUserFolders(UUID ownerId) {
        return folderRepository.findByOwnerIdAndIsDeletedFalse(ownerId);
    }

    /**
     * Retrieve a folder by its ID if it exists and is not deleted.
     *
     * Returns the folder if found and active, otherwise returns empty Optional.
     * Note: This method does NOT throw an exception; it returns Optional.
     * Use this for queries where absence of the folder is expected and handled.
     *
     * Performance: O(log n) primary key lookup
     *
     * @param folderId The UUID of the folder to retrieve
     * @return Optional containing the Folder if found and active, empty otherwise
     *
     * Example:
     *   Optional<Folder> folder = folderService.getFolderById(folderId);
     *   if (folder.isPresent()) {
     *       // Use folder
     *   } else {
     *       // Handle missing folder
     *   }
     */
    @Transactional(readOnly = true)
    public Optional<Folder> getFolderById(UUID folderId) {
        return folderRepository.findByFolderIdAndIsDeletedFalse(folderId);
    }

    /**
     * Get a folder by ID or throw exception if not found or deleted.
     *
     * Convenience method for cases where folder must exist. Throws FolderNotFoundException
     * if folder doesn't exist or has been soft-deleted.
     *
     * Performance: O(log n) primary key lookup
     *
     * @param folderId The UUID of the folder to retrieve
     * @return The Folder entity (guaranteed non-null and active)
     * @throws FolderNotFoundException if folder doesn't exist or is deleted
     *
     * Example:
     *   Folder folder = folderService.getFolderByIdOrThrow(folderId);
     */
    @Transactional(readOnly = true)
    public Folder getFolderByIdOrThrow(UUID folderId) {
        return folderRepository.findByFolderIdAndIsDeletedFalse(folderId)
            .orElseThrow(() -> new FolderNotFoundException(folderId));
    }

    /**
     * Soft-delete a folder (mark as deleted without removing from database).
     *
     * Sets isDeleted=true and records the deletion timestamp for audit trail.
     * The folder remains in the database for compliance and audit purposes.
     *
     * Performance: O(log n) for single folder
     * Transaction: Atomic operation with audit trail
     *
     * @param folderId The UUID of the folder to soft-delete
     * @throws FolderNotFoundException if folder doesn't exist or is already deleted
     *
     * Example:
     *   folderService.softDeleteFolder(folderId);
     *   // Folder now has isDeleted=true, deletedAt=now, but remains in DB
     */
    @Transactional
    public void softDeleteFolder(UUID folderId) throws FolderNotFoundException {
        // Retrieve folder
        Folder folder = getFolderByIdOrThrow(folderId);

        // Soft delete the folder
        folder.softDelete();
        folderRepository.save(folder);

        // Log soft deletion (security audit)
        log.info("Folder soft-deleted: folderId={}, ownerId={}, deletedAt={}", 
            folderId, folder.getOwnerId(), folder.getDeletedAt());
    }

    /**
     * Recursively soft-delete a folder and all its child folders.
     *
     * Performs a recursive soft-delete of the entire folder hierarchy:
     * 1. Marks the specified folder as deleted
     * 2. Recursively marks all child folders as deleted
     * 3. Persists all changes atomically
     *
     * This is useful for cleaning up entire folder structures while maintaining
     * audit trail compliance.
     *
     * Performance: O(log n + h) where h = total folders in hierarchy
     * Transaction: Single atomic transaction for consistency
     * Caution: This operation affects many folders; use with care
     *
     * @param folderId The UUID of the root folder to recursively delete
     * @throws FolderNotFoundException if folder doesn't exist or is already deleted
     *
     * Example:
     *   // Delete "Projects" folder and all subfolders recursively
     *   folderService.softDeleteFolderRecursive(projectsFolderId);
     */
    @Transactional
    public void softDeleteFolderRecursive(UUID folderId) {
        // Retrieve folder
        Folder folder = getFolderByIdOrThrow(folderId);

        // Recursively delete this folder and all children
        recursivelyDeleteFolder(folder);

        // Log recursive deletion (security audit)
        log.warn("Folder recursively soft-deleted (including children): folderId={}, ownerId={}", 
            folderId, folder.getOwnerId());
    }

    /**
     * Internal helper method to recursively soft-delete a folder and its children.
     *
     * This method is called internally during recursive delete operations.
     * It marks the folder as deleted and recursively processes all child folders.
     *
     * @param folder The folder to recursively delete
     */
    private void recursivelyDeleteFolder(Folder folder) {
        // Mark this folder as deleted
        folder.softDelete();
        folderRepository.save(folder);

        // Recursively delete all child folders
        List<Folder> children = folderRepository.findByParentFolderIdAndIsDeletedFalse(folder.getFolderId());
        for (Folder child : children) {
            recursivelyDeleteFolder(child);
        }
    }

    /**
     * Hard-delete a folder from the database (permanent removal).
     *
     * WARNING: This operation is permanent and cannot be undone. Use only for:
     * - Testing purposes
     * - Admin cleanup operations
     * - GDPR data deletion (ensure all related files are also deleted)
     *
     * Hard delete removes the folder completely from the database, unlike soft
     * delete which marks it as deleted but retains the record for audit.
     *
     * Safety Considerations:
     * - Ensure all files within the folder are deleted first
     * - Ensure all child folders are deleted first (due to foreign key constraints)
     * - Use with extreme caution in production
     * - Consider using softDeleteFolder instead for audit compliance
     *
     * Performance: O(log n) for single deletion
     *
     * @param folderId The UUID of the folder to permanently delete
     * @throws FolderNotFoundException if folder doesn't exist
     *
     * Example:
     *   // Production: Use soft delete instead
     *   folderService.softDeleteFolder(folderId);
     *
     *   // Testing/Admin only: Hard delete
     *   folderService.hardDeleteFolder(folderId);
     */
    @SuppressWarnings("null")
    @Transactional
    public void hardDeleteFolder(UUID folderId) {
        // Verify folder exists
        if (!folderRepository.existsById(folderId)) {
            throw new FolderNotFoundException(folderId);
        }

        // Hard delete from database
        folderRepository.deleteById(folderId);

        // Log hard deletion (security audit)
        log.warn("Folder hard-deleted (PERMANENT): folderId={}", folderId);
    }

    /**
     * Check if a folder exists and is not deleted.
     *
     * Useful for quick existence checks before performing operations.
     *
     * Performance: O(log n) indexed lookup
     *
     * @param folderId The UUID of the folder to check
     * @return true if folder exists and is active, false otherwise
     */
    @Transactional(readOnly = true)
    public boolean folderExists(UUID folderId) {
        return folderRepository.findByFolderIdAndIsDeletedFalse(folderId).isPresent();
    }

    /**
     * Restore a soft-deleted folder.
     *
     * Reverses a soft-delete operation by clearing the isDeleted flag and
     * deletion timestamp. The folder becomes queryable again.
     *
     * Note: This does NOT recursively restore child folders. Child folders must
     * be restored separately if desired.
     *
     * Performance: O(log n) for lookup + O(1) for update
     *
     * @param folderId The UUID of the folder to restore
     * @throws FolderNotFoundException if folder doesn't exist in database
     *         (this method doesn't filter by isDeleted, so it can restore any folder)
     *
     * Example:
     *   folderService.restoreFolder(deletedFolderId);
     */
    @SuppressWarnings("null")
    @Transactional
    public void restoreFolder(UUID folderId) {
        Folder folder = folderRepository.findById(folderId)
            .orElseThrow(() -> new FolderNotFoundException(folderId));

        folder.restore();
        folderRepository.save(folder);

        log.info("Folder restored: folderId={}, ownerId={}", folderId, folder.getOwnerId());
    }

    /**
     * Rename a folder.
     *
     * Updates the folder name to a new value. The folder must exist and not be deleted.
     *
     * Validation:
     * - newFolderName must not be null or blank
     *
     * Performance: O(log n) for lookup + O(1) for update
     *
     * @param folderId The UUID of the folder to rename
     * @param newFolderName The new name for the folder (must not be blank)
     * @return The renamed Folder entity
     * @throws FolderNotFoundException if folder doesn't exist or is deleted
     * @throws InvalidFolderNameException if newFolderName is null or blank
     *
     * Example:
     *   folderService.renameFolder(folderId, "New Folder Name");
     */
    @Transactional
    public Folder renameFolder(UUID folderId, String newFolderName) throws FolderNotFoundException, InvalidFolderNameException {
        if (newFolderName == null || newFolderName.isBlank()) {
            throw new InvalidFolderNameException("New folder name must not be null or blank");
        }

        Folder folder = getFolderByIdOrThrow(folderId);
        String oldFolderName = folder.getFolderName();
        
        folder.setFolderName(newFolderName);
        Folder renamedFolder = folderRepository.save(folder);

        log.info("Folder renamed: folderId={}, oldName={}, newName={}, ownerId={}", 
            folderId, oldFolderName, newFolderName, folder.getOwnerId());

        return renamedFolder;
    }

    /**
     * Move a folder to a new parent folder.
     *
     * Changes the parent folder of an existing folder, effectively moving it
     * in the hierarchy. The folder and new parent must exist and not be deleted.
     *
     * Validation:
     * - Folder must exist and not be deleted
     * - New parent must exist and not be deleted (if not null)
     * - Prevent circular references (cannot move folder to itself or its descendants)
     *
     * Performance: O(log n) for lookups + O(1) for update
     *
     * @param folderId The UUID of the folder to move
     * @param newParentFolderId The UUID of the new parent folder (null for root level)
     * @return The moved Folder entity
     * @throws FolderNotFoundException if folder or new parent doesn't exist or is deleted
     * @throws CircularReferenceFolderException if attempting to create circular reference
     *
     * Example:
     *   // Move folder to new parent
     *   folderService.moveFolder(folderId, newParentFolderId);
     *
     *   // Move folder to root level
     *   folderService.moveFolder(folderId, null);
     */
    @Transactional
    public Folder moveFolder(UUID folderId, UUID newParentFolderId) throws FolderNotFoundException, CircularReferenceFolderException {
        Folder folder = getFolderByIdOrThrow(folderId);

        // Prevent moving to self
        if (folderId.equals(newParentFolderId)) {
            throw new CircularReferenceFolderException(folderId, newParentFolderId);
        }

        // If new parent is specified, verify it exists and is not deleted
        if (newParentFolderId != null) {
            getFolderByIdOrThrow(newParentFolderId);

            // Prevent circular references: check if new parent is a descendant of this folder
            if (isDescendantOf(newParentFolderId, folderId)) {
                throw new CircularReferenceFolderException(folderId, newParentFolderId);
            }
        }

        UUID oldParentFolderId = folder.getParentFolderId();
        folder.setParentFolderId(newParentFolderId);
        Folder movedFolder = folderRepository.save(folder);

        log.info("Folder moved: folderId={}, oldParent={}, newParent={}, ownerId={}", 
            folderId, oldParentFolderId, newParentFolderId, folder.getOwnerId());

        return movedFolder;
    }

    /**
     * Check if a folder is a descendant of another folder in the hierarchy.
     *
     * Used to prevent circular references when moving folders.
     * Returns true if potentialDescendant is anywhere in the hierarchy below potentialAncestor.
     *
     * Performance: O(h) where h = height of folder hierarchy from ancestor to descendant
     *
     * @param potentialDescendant The folder to check as a descendant
     * @param potentialAncestor The folder to check as an ancestor
     * @return true if potentialDescendant is a descendant of potentialAncestor
     */
    private boolean isDescendantOf(@NonNull UUID potentialDescendant, UUID potentialAncestor) {
        Optional<Folder> current = folderRepository.findById(potentialDescendant);
        
        while (current.isPresent()) {
            Folder folder = current.get();
            
            // If we find the ancestor, potentialDescendant is indeed a descendant
            if (potentialAncestor.equals(folder.getParentFolderId())) {
                return true;
            }

            // Move up the hierarchy
            UUID parentId = folder.getParentFolderId();
            if (parentId != null) {
                current = folderRepository.findById(parentId);
            } else {
                // Reached root, ancestor not found
                break;
            }
        }

        return false;
    }
}
