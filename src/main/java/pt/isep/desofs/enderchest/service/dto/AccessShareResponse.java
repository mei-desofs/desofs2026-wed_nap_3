package pt.isep.desofs.enderchest.service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * DTO for access share response.
 * 
 * Returned after successful access share creation or retrieval.
 * Contains information about the granted access permissions.
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AccessShareResponse {

    /**
     * Unique identifier of this access share record (UUID v4).
     */
    private UUID shareId;

    /**
     * UUID of the shared resource (file or folder).
     */
    private UUID resourceId;

    /**
     * Type of resource being shared (FILE or FOLDER).
     */
    private String resourceType;

    /**
     * UUID of the user granted access.
     */
    private UUID grantedToUserId;

    /**
     * Role type of the access grant (OWNER, EDITOR, VIEWER).
     */
    private String roleType;

    /**
     * Timestamp when this access share was created.
     */
    private LocalDateTime createdAt;

    /**
     * Timestamp when this access share was revoked (if applicable).
     */
    private LocalDateTime revokedAt;
}
