package pt.isep.desofs.enderchest.service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * DTO for file version response.
 * 
 * Returned when retrieving file version history or specific version details.
 * Provides immutable version-specific metadata with integrity hash for verification.
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class FileVersionResponse {

    /**
     * Unique identifier of the file version (UUID v4).
     * Used to reference this specific version in subsequent API calls.
     */
    private UUID versionId;

    /**
     * Sequential version number starting from 1.
     * Combined with fileId to create unique version identifier.
     */
    private Integer versionNumber;

    /**
     * SHA-256 hash of file contents at this version.
     * Used for integrity verification and change detection.
     * Immutable after version creation.
     */
    private String sha256Hash;

    /**
     * Timestamp when this version was created/modified.
     * Used for version history timeline and audit trail.
     */
    private LocalDateTime modifiedAt;

    /**
     * User ID (JWT subject) who created/modified this version.
     * Extracted from SecurityContext for audit trail.
     */
    private String modifiedBy;

    /**
     * Human-readable description of changes in this version (optional).
     * Examples:
     * - "Initial upload"
     * - "Updated metadata"
     * - "Replaced with newer version"
     * - "Restored from backup"
     */
    private String changeDescription;

    /**
     * Creation timestamp for this version record.
     * Set automatically by JPA @PrePersist hook.
     */
    private LocalDateTime createdAt;
}
