package pt.isep.desofs.enderchest.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * AccessShare entity representing shared access to files and folders.
 *
 * This entity implements fine-grained access control for collaborative features.
 * It tracks permissions granted to users for specific resources (files or folders)
 * with role-based access control (OWNER, EDITOR, VIEWER).
 *
 * Aggregate root for access control operations. Provides polymorphic resource
 * identification through (resourceId, resourceType) composite key.
 *
 * Performance considerations:
 * - Composite index on (resourceId, resourceType, grantedToUserId) for fast access lookups
 * - CreationTimestamp automatically managed by JPA lifecycle
 * - resourceType as enum (STRING) for efficient filtering
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Entity
@Table(
    name = "access_shares",
    indexes = {
        @Index(
            name = "idx_access_shares_resource_grantee",
            columnList = "resource_id, resource_type, granted_to_user_id"
        ),
        @Index(name = "idx_access_shares_grantee", columnList = "granted_to_user_id"),
        @Index(name = "idx_access_shares_created_at", columnList = "created_at")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AccessShare {

    /**
     * Resource type enumeration.
     *
     * Defines the type of resource being shared:
     * - FILE: Shared access to individual files
     * - FOLDER: Shared access to folder and its contents
     */
    public enum ResourceType {
        FILE,
        FOLDER
    }

    /**
     * Role type enumeration.
     *
     * Defines the level of access granted:
     * - OWNER: Full control including sharing and deletion
     * - EDITOR: Modify and read, but cannot delete or reshare
     * - VIEWER: Read-only access
     */
    public enum RoleType {
        OWNER,
        EDITOR,
        VIEWER
    }

    /**
     * Unique identifier for this access share record (UUID v4, auto-generated).
     * Using UUID prevents sequential ID enumeration attacks.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "share_id", nullable = false, updatable = false, columnDefinition = "UUID")
    private UUID shareId;

    /**
     * Resource identifier (UUID pointing to either File or Folder).
     *
     * Combined with resourceType, forms a polymorphic reference to the shared resource.
     * Not a foreign key - allows flexibility in resource types.
     */
    @NotNull(message = "Resource ID must not be null")
    @Column(name = "resource_id", nullable = false, columnDefinition = "UUID")
    private UUID resourceId;

    /**
     * Type of resource being shared (FILE or FOLDER).
     *
     * Enum stored as string for clarity and compatibility.
     * Used with resourceId to identify the actual resource.
     */
    @NotNull(message = "Resource type must not be null")
    @Column(name = "resource_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private ResourceType resourceType;

    /**
     * User ID (UUID foreign key reference to User entity).
     *
     * The user to whom this access is granted.
     * Many AccessShare records can point to the same User.
     */
    @NotNull(message = "Granted to user ID must not be null")
    @Column(name = "granted_to_user_id", nullable = false, columnDefinition = "UUID")
    private UUID grantedToUserId;

    /**
     * Relationship: Many access shares can be granted to one user.
     *
     * Lazy loaded by default for performance optimization.
     * Join on grantedToUserId to User.userId.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "granted_to_user_id", referencedColumnName = "user_id", insertable = false, updatable = false)
    private User grantedToUser;

    /**
     * Role type defining the level of access (OWNER, EDITOR, VIEWER).
     *
     * Enum stored as string for clarity in audit logs.
     * Determines what operations the user can perform on the resource.
     */
    @NotNull(message = "Role type must not be null")
    @Column(name = "role_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private RoleType roleType;

    /**
     * Timestamp when this access share was created.
     *
     * Set automatically by JPA lifecycle hook.
     * Immutable after creation for audit trail compliance.
     */
    @NotNull(message = "Created at timestamp must not be null")
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime createdAt;

    /**
     * Constructor with essential access share metadata.
     *
     * @param resourceId UUID of the shared resource (file or folder)
     * @param resourceType Type of resource being shared (FILE or FOLDER)
     * @param grantedToUserId UUID of the user granted access
     * @param roleType Level of access (OWNER, EDITOR, VIEWER)
     */
    public AccessShare(UUID resourceId, ResourceType resourceType, UUID grantedToUserId, RoleType roleType) {
        this.resourceId = resourceId;
        this.resourceType = resourceType;
        this.grantedToUserId = grantedToUserId;
        this.roleType = roleType;
    }

    // ============ Business Logic Methods ============

    /**
     * Check if this access share grants owner-level permissions.
     *
     * @return true if role type is OWNER, false otherwise
     */
    public boolean isOwner() {
        return this.roleType == RoleType.OWNER;
    }

    /**
     * Check if this access share grants editor-level permissions or higher.
     *
     * @return true if role type is OWNER or EDITOR, false otherwise
     */
    public boolean canEdit() {
        return this.roleType == RoleType.OWNER || this.roleType == RoleType.EDITOR;
    }

    /**
     * Check if this access share grants view permissions (any level).
     *
     * @return true (all role types have view access)
     */
    public boolean canView() {
        return true;
    }
}
