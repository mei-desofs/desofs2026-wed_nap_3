package pt.isep.desofs.enderchest.service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.UUID;

/**
 * DTO for access share creation request.
 * 
 * Contains the information needed to grant access to a file or folder
 * to another user with a specific role (OWNER, EDITOR, VIEWER).
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AccessShareRequest {

    /**
     * UUID of the resource being shared (file or folder).
     */
    @NotNull(message = "Resource ID must not be null")
    private UUID resourceId;

    /**
     * Type of resource being shared (FILE or FOLDER).
     */
    @NotBlank(message = "Resource type must not be blank")
    private String resourceType;

    /**
     * UUID of the user being granted access.
     */
    @NotNull(message = "Granted to user ID must not be null")
    private UUID grantedToUserId;

    /**
     * Role type for the access grant (OWNER, EDITOR, VIEWER).
     * Determines the level of permissions the user has on the resource.
     */
    @NotBlank(message = "Role type must not be blank")
    private String roleType;
}
