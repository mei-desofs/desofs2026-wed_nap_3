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
 * AuditLog entity for comprehensive audit trail of all system actions.
 * 
 * Implements FR-08 (Audit Logging) and SDR-NEW-12 (Comprehensive Audit Trail).
 * Tracks all significant actions (file upload/download/delete, folder operations, sharing actions)
 * without storing sensitive data (passwords, tokens, file content).
 * 
 * Performance considerations:
 * - userId indexed for fast audit trail queries per user
 * - action indexed for filtering by operation type
 * - timestamp indexed for time-range queries
 * - resourceId indexed for finding all actions on a specific resource
 * - Composite index (userId, timestamp) for chronological audit trails
 * 
 * Security considerations:
 * - No passwords, tokens, or sensitive content stored
 * - ipAddress recorded for geographic audit trail
 * - All timestamps immutable (audit trail integrity)
 * - Action and resourceType are enum-like strings (predefined values only)
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Entity
@Table(
    name = "audit_logs",
    indexes = {
        @Index(name = "idx_audit_logs_user_id", columnList = "user_id"),
        @Index(name = "idx_audit_logs_action", columnList = "action"),
        @Index(name = "idx_audit_logs_timestamp", columnList = "timestamp"),
        @Index(name = "idx_audit_logs_resource_id", columnList = "resource_id"),
        @Index(name = "idx_audit_logs_user_timestamp", columnList = "user_id, timestamp"),
        @Index(name = "idx_audit_logs_resource_type", columnList = "resource_type")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AuditLog {

    /**
     * Unique identifier (UUID v4, auto-generated).
     * Using UUID prevents sequential ID enumeration attacks.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false, columnDefinition = "UUID")
    private UUID id;

    /**
     * Type of action performed.
     * Predefined values: FILE_UPLOAD, FILE_DOWNLOAD, FILE_DELETE, FOLDER_CREATE, FOLDER_DELETE, SHARE_GRANT, SHARE_REVOKE
     * Enum-like string for filtering and analysis.
     */
    @NotBlank(message = "Action must not be blank")
    @Column(name = "action", nullable = false, length = 50)
    private String action;

    /**
     * User ID (from JWT subject) who performed the action.
     * Extracted from SecurityContext for audit trail.
     * Indexed for fast "all actions by user" queries.
     */
    @NotBlank(message = "User ID must not be blank")
    @Column(name = "user_id", nullable = false, length = 255)
    private String userId;

    /**
     * Type of resource affected by the action.
     * Predefined values: FILE, FOLDER, SHARE, DOWNLOAD
     * Used to categorize and filter audit events.
     */
    @NotBlank(message = "Resource type must not be blank")
    @Column(name = "resource_type", nullable = false, length = 50)
    private String resourceType;

    /**
     * UUID of the resource (file, folder, share, etc.) affected by the action.
     * Nullable for system-wide actions.
     * Indexed for finding all actions on a specific resource.
     */
    @Column(name = "resource_id", columnDefinition = "UUID")
    private UUID resourceId;

    /**
     * JSON details of the action (non-sensitive metadata).
     * Examples:
     * - {"fileName": "document.pdf", "fileSize": 1024}
     * - {"folderName": "My Folder"}
     * - {"grantedTo": "user@example.com", "role": "VIEWER"}
     * 
     * IMPORTANT: Never includes passwords, tokens, file content, or sensitive data
     * 
     * Nullable for simple actions without additional context.
     */
    @Column(name = "details", columnDefinition = "TEXT")
    private String details;

    /**
     * Timestamp when the action occurred.
     * Set automatically by JPA @PrePersist hook.
     * Immutable after creation for audit integrity.
     * Used for chronological audit trail reconstruction.
     */
    @NotNull(message = "Timestamp must not be null")
    @Column(name = "timestamp", nullable = false, updatable = false, columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime timestamp;

    /**
     * IP address of the client that initiated the action.
     * Used for geographic audit trail and security analysis.
     * Optional if behind reverse proxy where IP is not available.
     */
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    /**
     * Constructor for creating an audit log entry.
     * 
     * @param action The action type (e.g., "FILE_UPLOAD")
     * @param userId The user who performed the action
     * @param resourceType The type of resource affected
     * @param resourceId The UUID of the resource (nullable)
     * @param details JSON details of the action (nullable, no sensitive data)
     * @param ipAddress The IP address of the client (nullable)
     */
    public AuditLog(String action, String userId, String resourceType, UUID resourceId, 
                   String details, String ipAddress) {
        this.action = action;
        this.userId = userId;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.details = details;
        this.ipAddress = ipAddress;
    }

    /**
     * JPA @PrePersist hook: Initialize timestamp on creation.
     * Called automatically before the entity is inserted into the database.
     */
    @PrePersist
    protected void onCreate() {
        this.timestamp = LocalDateTime.now();
    }

    // ============ Audit Action Constants ============
    
    /**
     * Predefined action types for consistency and filtering.
     */
    public static final class Action {
        public static final String FILE_UPLOAD = "FILE_UPLOAD";
        public static final String FILE_DOWNLOAD = "FILE_DOWNLOAD";
        public static final String FILE_DELETE = "FILE_DELETE";
        public static final String FOLDER_CREATE = "FOLDER_CREATE";
        public static final String FOLDER_DELETE = "FOLDER_DELETE";
        public static final String SHARE_GRANT = "SHARE_GRANT";
        public static final String SHARE_REVOKE = "SHARE_REVOKE";
    }

    /**
     * Predefined resource types for consistency and filtering.
     */
    public static final class ResourceType {
        public static final String FILE = "FILE";
        public static final String FOLDER = "FOLDER";
        public static final String SHARE = "SHARE";
        public static final String DOWNLOAD = "DOWNLOAD";
    }
}
