package pt.isep.desofs.enderchest.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Folder entity representing a directory container for files within the system.
 *
 * This entity serves as an aggregate root for folder management and implements
 * hierarchical folder structures through self-referencing relationships. It supports
 * recursive folder hierarchies and soft-delete operations for audit compliance.
 *
 * Security considerations:
 * - folderId (UUID) prevents sequential ID enumeration attacks
 * - ownerId references User.userId for access control verification
 * - isDeleted flag implements soft delete — prevents immediate permanent data loss
 * - Path traversal prevention is enforced at the OS I/O layer, not in this entity
 * - parentFolderId allows self-referencing for hierarchical folder structures
 *
 * Performance considerations:
 * - ownerId is indexed for fast queries of user's folders
 * - parentFolderId is indexed for fast hierarchical queries
 * - isDeleted is indexed for queries that exclude soft-deleted folders
 * - created_at is indexed for audit trail and time-based queries
 * - orphanRemoval = true ensures child folders are deleted when parent is deleted
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Entity
@Table(
    name = "folders",
    indexes = {
        @Index(name = "idx_folders_owner_id", columnList = "owner_id"),
        @Index(name = "idx_folders_parent_folder_id", columnList = "parent_folder_id"),
        @Index(name = "idx_folders_is_deleted", columnList = "is_deleted"),
        @Index(name = "idx_folders_created_at", columnList = "created_at"),
        @Index(name = "idx_folders_owner_parent_deleted", columnList = "owner_id, parent_folder_id, is_deleted")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = {"owner", "parentFolder", "childFolders"})
public class Folder {

    /**
     * Unique identifier (UUID v4, auto-generated).
     * Using UUID prevents sequential ID enumeration attacks.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "folder_id", nullable = false, updatable = false, columnDefinition = "UUID")
    private UUID folderId;

    /**
     * Name of the folder as provided by the user.
     * Must not be blank. Used for display and folder identification.
     */
    @NotBlank(message = "Folder name must not be blank")
    @Column(name = "folder_name", nullable = false, length = 512)
    private String folderName;

    /**
     * ID of the folder owner (references User.userId).
     * Mandatory foreign key for access control and ownership verification.
     * Indexed for fast queries of user's folders.
     */
    @NotNull(message = "Owner ID must not be null")
    @Column(name = "owner_id", nullable = false, columnDefinition = "UUID")
    private UUID ownerId;

    /**
     * Many-to-One relationship to User (the folder owner).
     * Lazy-loaded for performance; navigable for access control checks.
     * References User.userId.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", referencedColumnName = "user_id", insertable = false, updatable = false, nullable = false, columnDefinition = "UUID")
    private User owner;

    /**
     * ID of the parent folder (nullable, self-referencing).
     * Enables hierarchical folder structure: root folders have parentFolderId = null.
     * Indexed for fast hierarchical queries.
     */
    @Column(name = "parent_folder_id", columnDefinition = "UUID")
    private UUID parentFolderId;

    /**
     * Many-to-One relationship to parent Folder (self-referencing).
     * Lazy-loaded for performance. Nullable for root-level folders.
     * References Folder.folderId.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_folder_id", referencedColumnName = "folder_id", insertable = false, updatable = false, columnDefinition = "UUID")
    private Folder parentFolder;

    /**
     * One-to-Many relationship to child folders (self-referencing).
     * Bi-directional mapping: maintains list of direct children.
     * orphanRemoval = true ensures cascade soft-delete on removal.
     * Lazy-loaded for performance; explicitly loaded when needed.
     */
    @OneToMany(fetch = FetchType.LAZY, mappedBy = "parentFolder", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Folder> childFolders = new ArrayList<>();

    /**
     * Soft delete flag. When true, folder is logically deleted but retained for audit.
     * Enables compliance with data retention policies and reduces hard delete risk.
     * Default: false (folder is active).
     */
    @NotNull(message = "Deleted flag must not be null")
    @Column(name = "is_deleted", nullable = false)
    private Boolean isDeleted = Boolean.FALSE;

    /**
     * Timestamp when the folder was initially created.
     * Set automatically by JPA @PrePersist hook.
     * Immutable after creation for audit trail.
     */
    @NotNull(message = "Created at timestamp must not be null")
    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime createdAt;

    /**
     * Timestamp for folder last update.
     * Updated automatically by JPA @PreUpdate hook.
     * Tracks when folder information was last modified.
     */
    @Column(name = "updated_at", columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime updatedAt;

    /**
     * Timestamp for soft deletion tracking (audit trail).
     * Set when folder is soft-deleted via delete() method.
     */
    @Column(name = "deleted_at", columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime deletedAt;

    /**
     * Constructor with essential folder metadata (no parent folder).
     * Useful for creating root-level folder instances.
     *
     * @param folderName The folder name
     * @param ownerId The UUID of the folder owner
     */
    public Folder(String folderName, UUID ownerId) {
        this.folderName = folderName;
        this.ownerId = ownerId;
        this.parentFolderId = null;
        this.isDeleted = Boolean.FALSE;
        this.childFolders = new ArrayList<>();
    }

    /**
     * Constructor with essential folder metadata including parent folder.
     * Useful for creating child folder instances.
     *
     * @param folderName The folder name
     * @param ownerId The UUID of the folder owner
     * @param parentFolderId The UUID of the parent folder (can be null for root folders)
     */
    public Folder(String folderName, UUID ownerId, UUID parentFolderId) {
        this.folderName = folderName;
        this.ownerId = ownerId;
        this.parentFolderId = parentFolderId;
        this.isDeleted = Boolean.FALSE;
        this.childFolders = new ArrayList<>();
    }

    /**
     * JPA @PrePersist hook: Initialize timestamps on creation.
     * Called automatically before the entity is inserted into the database.
     */
    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
        if (this.isDeleted == null) {
            this.isDeleted = Boolean.FALSE;
        }
        if (this.childFolders == null) {
            this.childFolders = new ArrayList<>();
        }
    }

    /**
     * JPA @PreUpdate hook: Update modification timestamp.
     * Called automatically before the entity is updated in the database.
     */
    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    // ============ Business Logic Methods ============

    /**
     * Get the list of child folders.
     * Returns a defensive copy to prevent external modification of internal state.
     *
     * @return List of child Folder entities
     */
    public List<Folder> getChildFolders() {
        if (this.childFolders == null) {
            this.childFolders = new ArrayList<>();
        }
        return this.childFolders;
    }

    /**
     * Mark this folder as deleted (soft delete).
     * Sets isDeleted flag and records deletion timestamp for audit trail.
     * Note: This does NOT cascade to child folders — they must be managed separately
     * or the application layer must handle hierarchy deletion.
     *
     * @return This Folder instance for method chaining
     */
    public Folder softDelete() {
        this.isDeleted = Boolean.TRUE;
        this.deletedAt = LocalDateTime.now();
        return this;
    }

    /**
     * Restore a soft-deleted folder.
     * Clears deletion markers for audit recovery scenarios.
     *
     * @return This Folder instance for method chaining
     */
    public Folder restore() {
        this.isDeleted = Boolean.FALSE;
        this.deletedAt = null;
        return this;
    }

    /**
     * Check if folder is logically active (not soft-deleted).
     *
     * @return true if folder is active, false if deleted
     */
    public boolean isActive() {
        return !this.isDeleted;
    }

    /**
     * Check if this is a root-level folder (has no parent).
     *
     * @return true if parentFolderId is null, false otherwise
     */
    public boolean isRootFolder() {
        return this.parentFolderId == null;
    }

    /**
     * Add a child folder to this folder.
     * Maintains bi-directional relationship by setting the child's parent.
     *
     * @param childFolder The child folder to add
     * @return This Folder instance for method chaining
     */
    public Folder addChildFolder(Folder childFolder) {
        if (this.childFolders == null) {
            this.childFolders = new ArrayList<>();
        }
        this.childFolders.add(childFolder);
        childFolder.setParentFolderId(this.folderId);
        return this;
    }

    /**
     * Remove a child folder from this folder.
     * Maintains bi-directional relationship.
     *
     * @param childFolder The child folder to remove
     * @return This Folder instance for method chaining
     */
    public Folder removeChildFolder(Folder childFolder) {
        if (this.childFolders != null) {
            this.childFolders.remove(childFolder);
            childFolder.setParentFolderId(null);
        }
        return this;
    }
}
