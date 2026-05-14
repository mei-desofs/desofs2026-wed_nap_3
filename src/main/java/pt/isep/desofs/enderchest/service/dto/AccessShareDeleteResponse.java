package pt.isep.desofs.enderchest.service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * DTO for access share deletion response.
 * 
 * Returned after successful access share deletion (revocation).
 * Confirms the revocation and provides audit trail information.
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class AccessShareDeleteResponse {

    /**
     * Unique identifier of the revoked access share (UUID v4).
     */
    private UUID shareId;

    /**
     * Timestamp when the access share was revoked.
     */
    private LocalDateTime revokedAt;

    /**
     * Status message confirming the revocation.
     */
    private String message;
}
