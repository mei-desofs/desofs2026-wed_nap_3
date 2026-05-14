package pt.isep.desofs.enderchest.service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.UUID;

/**
 * DTO for user profile response.
 * 
 * Contains user identity and storage quota information.
 * Returned when querying the authenticated user's profile.
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class UserProfileResponse {

    /**
     * Unique identifier of the user (UUID v4).
     */
    private UUID userId;

    /**
     * Username for user identification and login.
     */
    private String username;

    /**
     * Email address of the user.
     */
    private String email;

    /**
     * Full name of the user (first name + last name).
     */
    private String fullName;

    /**
     * Total storage quota allocated to the user (in bytes).
     * Typically a fixed value per user or determined by subscription tier.
     */
    private Long storageQuota;

    /**
     * Amount of storage currently used by the user (in bytes).
     * Calculated as the sum of all file versions owned by this user.
     */
    private Long usedStorage;

    /**
     * Amount of storage available to the user (in bytes).
     * Calculated as: storageQuota - usedStorage
     */
    private Long availableStorage;
}
