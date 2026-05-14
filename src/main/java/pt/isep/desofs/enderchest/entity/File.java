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
import java.util.UUID;

/**
 * File entity representing a stored file with metadata.
 * 
 * This entity implements soft-delete pattern for audit compliance and tracks
 * file metadata for deduplication, access control, and version management.
 * 
 * Performance considerations:
 * - sha256Hash is indexed (UNIQUE) for deduplication lookups
 * - uploadedBy + isDeleted indexed for fast user file queries
 * - uploadedAt indexed for time-based queries
 * - Uses UUID for ID to prevent sequential ID guessing attacks
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Entity
@Table(
    name = "files",
    indexes = {
        @Index(name = "idx_files_sha256_hash", columnList = "sha256_hash", unique = true),
        @Index(name = "idx_files_uploaded_by_not_deleted", columnList = "uploaded_by, is_deleted"),
        @Index(name = "idx_files_uploaded_at", columnList = "uploaded_at"),
        @Index(name = "idx_files_is_deleted", columnList = "is_deleted"),
        @Index(name = "idx_files_created_at", columnList = "created_at"),
        @Index(name = "idx_files_folder_id_not_deleted", columnList = "folder_id, is_deleted"),
        @Index(name = "idx_files_folder_id", columnList = "folder_id")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "storageLocation")
public class File {

    /**
     * Unique identifier (UUID v4, auto-generated).
     * Using UUID prevents sequential ID enumeration attacks.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false, columnDefinition = "UUID")
    private UUID id;

    /**
     * Original file name as provided by the user during upload.
     * Retained for user-friendly display and audit purposes.
     */
    @NotBlank(message = "Original file name must not be blank")
    @Column(name = "original_file_name", nullable = false, length = 512)
    private String originalFileName;

    /**
     * Sanitized, UUID-based file name used for storage.
     * This prevents directory traversal attacks and name collisions.
     */
    @NotBlank(message = "Stored file name must not be blank")
    @Column(name = "stored_file_name", nullable = false, unique = true, length = 256)
    private String storedFileName;

    /**
     * SHA-256 hash of file contents for deduplication and integrity verification.
     * Immutable after creation. Used to detect duplicate file uploads.
     * Indexed for fast lookup (sub-100ms).
     */
    @NotBlank(message = "SHA-256 hash must not be blank")
    @Column(name = "sha256_hash", nullable = false, unique = true, length = 64, updatable = false)
    private String sha256Hash;

    /**
     * File size in bytes. Used for quota enforcement and transfer validation.
     */
    @NotNull(message = "File size must not be null")
    @Column(name = "file_size", nullable = false)
    private Long fileSize;

    /**
     * MIME type (content type) detected via Apache Tika magic bytes verification.
     * Used for security validation (T-06 Web Shell mitigation).
     */
    @NotBlank(message = "MIME type must not be blank")
    @Column(name = "mime_type", nullable = false, length = 127)
    private String mimeType;

    /**
     * Timestamp when the file was initially uploaded.
     * Set automatically by JPA @PrePersist hook.
     */
    @NotNull(message = "Upload timestamp must not be null")
    @Column(name = "uploaded_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime uploadedAt;

    /**
     * User ID (JWT subject) who uploaded the file.
     * Extracted from SecurityContext for audit trail and access control.
     */
    @NotBlank(message = "Uploaded by must not be blank")
    @Column(name = "uploaded_by", nullable = false, length = 255)
    private String uploadedBy;

    /**
     * Storage location reference (file path or S3 URI).
     * Abstracted to support multiple storage backends.
     */
    @NotBlank(message = "Storage location must not be blank")
    @Column(name = "storage_location", nullable = false, length = 1024)
    private String storageLocation;

    /**
     * Timestamp for tracking soft updates (not persisted as column update).
     * Used for audit compliance to distinguish uploads from metadata changes.
     */
    @Column(name = "updated_at", columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime updatedAt;

    /**
     * Soft delete flag. When true, file is logically deleted but retained for audit.
     * Enables compliance with data retention policies and reduces hard delete risk.
     */
    @NotNull(message = "Deleted flag must not be null")
    @Column(name = "is_deleted", nullable = false)
    private Boolean isDeleted = Boolean.FALSE;

    /**
     * Timestamp for soft deletion tracking (audit trail).
     */
    @Column(name = "deleted_at", columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime deletedAt;

    /**
     * Timestamp for creation tracking.
     * Set automatically by JPA @PrePersist hook.
     */
    @NotNull(message = "Created at timestamp must not be null")
    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime createdAt;

    /**
     * Foreign key ID of the parent folder (nullable for root-level files).
     * Used for querying files by folder. Managed by the folder relationship mapping.
     * Set insertable=false, updatable=false to avoid duplication with @ManyToOne mapping.
     */
    @Column(name = "folder_id", insertable = false, updatable = false, columnDefinition = "UUID")
    private UUID folderId;

    /**
     * Many-to-one relationship to Folder (nullable for root-level files).
     * Defines the parent folder containing this file.
     * Lazy-loaded to improve query performance.
     * Optional relationship - null indicates root-level file.
     * 
     * The folder_id column is managed by this relationship mapping.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "folder_id", referencedColumnName = "folder_id", nullable = true, updatable = true, foreignKey = @ForeignKey(name = "fk_files_folder_id"))
    private Folder folder;

    /**
     * Constructor with essential file metadata.
     * Useful for creating File instances with required fields only.
     * 
     * @param originalFileName The name provided by the user
     * @param storedFileName UUID-based sanitized name
     * @param sha256Hash SHA-256 hash of file contents
     * @param fileSize Size in bytes
     * @param mimeType Content type (validated via magic bytes)
     * @param uploadedBy User ID (JWT subject)
     * @param storageLocation File path or S3 URI
     */
    public File(String originalFileName, String storedFileName, String sha256Hash,
                Long fileSize, String mimeType, String uploadedBy, String storageLocation) {
        this.originalFileName = originalFileName;
        this.storedFileName = storedFileName;
        this.sha256Hash = sha256Hash;
        this.fileSize = fileSize;
        this.mimeType = mimeType;
        this.uploadedBy = uploadedBy;
        this.storageLocation = storageLocation;
        this.isDeleted = Boolean.FALSE;
        this.folder = null;
    }

    /**
     * JPA @PrePersist hook: Initialize timestamps on creation.
     * Called automatically before the entity is inserted into the database.
     */
    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.uploadedAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
        if (this.isDeleted == null) {
            this.isDeleted = Boolean.FALSE;
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
     * Mark this file as deleted (soft delete).
     * Sets isDeleted flag and records deletion timestamp for audit trail.
     * Enables file recovery and maintains audit compliance.
     * 
     * @return This File instance for method chaining
     */
    public File softDelete() {
        this.isDeleted = Boolean.TRUE;
        this.deletedAt = LocalDateTime.now();
        return this;
    }

    /**
     * Mark this file as deleted (soft delete).
     * Sets isDeleted flag and records deletion timestamp for audit trail.
     * 
     * Deprecated: Use softDelete() for clarity. This method maintained for backward compatibility.
     * 
     * @return This File instance for method chaining
     */
    @Deprecated(since = "1.0", forRemoval = false)
    public File delete() {
        return this.softDelete();
    }

    /**
     * Restore a soft-deleted file.
     * Clears deletion markers for audit recovery scenarios.
     * 
     * @return This File instance for method chaining
     */
    public File restore() {
        this.isDeleted = Boolean.FALSE;
        this.deletedAt = null;
        return this;
    }

    /**
     * Check if file is logically active (not soft-deleted).
     * 
     * @return true if file is active, false if deleted
     */
    public boolean isActive() {
        return !this.isDeleted;
    }
}
