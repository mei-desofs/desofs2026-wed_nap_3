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
 * FileVersion entity for audit trail and version history tracking.
 * 
 * Implements complete audit trail of file changes with version numbering,
 * hash tracking at each version, and change descriptions for compliance.
 * 
 * Performance considerations:
 * - Indexed by fileId for fast version history retrieval
 * - Indexed by modifiedAt for time-range queries
 * - Supports cascading operations from parent File entity
 * - Immutable once persisted (update operations create new versions, not modify existing)
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Entity
@Table(
    name = "file_versions",
    indexes = {
        @Index(name = "idx_file_versions_file_id", columnList = "file_id"),
        @Index(name = "idx_file_versions_modified_at", columnList = "modified_at"),
        @Index(name = "idx_file_versions_file_id_version", columnList = "file_id, version_number", unique = true)
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "file")
public class FileVersion {

    /**
     * Unique identifier (UUID v4, auto-generated).
     * Each version gets a unique identifier for tracking and audit purposes.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false, columnDefinition = "UUID")
    private UUID id;

    /**
     * Foreign key reference to the parent File entity.
     * Uses LAZY loading to prevent N+1 queries when fetching versions.
     * Cascade DELETE ensures versions are removed when parent file is hard-deleted.
     */
    @NotNull(message = "File ID must not be null")
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "file_id", nullable = false, updatable = false, foreignKey = @ForeignKey(name = "fk_file_versions_file_id"))
    private File file;

    /**
     * Version number for audit trail (sequential starting from 1).
     * Combined with fileId to create unique version identifier.
     * Enables efficient version history queries and rollback scenarios.
     */
    @NotNull(message = "Version number must not be null")
    @Column(name = "version_number", nullable = false)
    private Integer versionNumber;

    /**
     * SHA-256 hash of file contents at this version.
     * Immutable after creation. Enables integrity verification for each version.
     * Allows detecting content changes vs metadata-only updates.
     */
    @NotBlank(message = "SHA-256 hash must not be blank")
    @Column(name = "sha256_hash", nullable = false, length = 64, updatable = false)
    private String sha256Hash;

    /**
     * Timestamp when this version was created/modified.
     * Set automatically by JPA @PrePersist hook.
     * Used for time-based queries and audit timeline reconstruction.
     */
    @NotNull(message = "Modified timestamp must not be null")
    @Column(name = "modified_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime modifiedAt;

    /**
     * User ID (JWT subject) who created/modified this version.
     * Extracted from SecurityContext for audit trail and access control.
     * Enables tracking responsibility for changes.
     */
    @NotBlank(message = "Modified by must not be blank")
    @Column(name = "modified_by", nullable = false, length = 255, updatable = false)
    private String modifiedBy;

    /**
     * Human-readable description of changes in this version (optional).
     * Examples:
     * - "Initial upload"
     * - "Updated metadata"
     * - "Replaced with newer version"
     * - "Restored from backup"
     */
    @Column(name = "change_description", length = 1024, updatable = false)
    private String changeDescription;

    /**
     * Timestamp for creation tracking.
     * Set automatically by JPA @PrePersist hook.
     */
    @NotNull(message = "Created at timestamp must not be null")
    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime createdAt;

    /**
     * Constructor for creating a new file version with required fields.
     * 
     * @param file The parent File entity
     * @param versionNumber Incremental version number
     * @param sha256Hash Hash of file contents at this version
     * @param modifiedBy User who made the change
     * @param changeDescription Optional description of what changed
     */
    public FileVersion(File file, Integer versionNumber, String sha256Hash, 
                      String modifiedBy, String changeDescription) {
        this.file = file;
        this.versionNumber = versionNumber;
        this.sha256Hash = sha256Hash;
        this.modifiedBy = modifiedBy;
        this.changeDescription = changeDescription;
    }

    /**
     * JPA @PrePersist hook: Initialize timestamps on creation.
     * Called automatically before the entity is inserted into the database.
     */
    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.modifiedAt = LocalDateTime.now();
    }

    // ============ Business Logic Methods ============

    /**
     * Check if this version represents the same content as another version.
     * Used to detect content changes vs metadata-only updates.
     * 
     * @param other The other FileVersion to compare
     * @return true if both versions have identical SHA-256 hashes
     */
    public boolean isSameContent(FileVersion other) {
        return this.sha256Hash.equals(other.getSha256Hash());
    }

    /**
     * Check if this is the first version of the file.
     * 
     * @return true if versionNumber equals 1
     */
    public boolean isInitialVersion() {
        return this.versionNumber == 1;
    }
}
