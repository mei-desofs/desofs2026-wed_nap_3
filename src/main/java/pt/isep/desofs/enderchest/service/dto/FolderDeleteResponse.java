package pt.isep.desofs.enderchest.service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * DTO for folder deletion response.
 * 
 * Returned after successful folder deletion operation (soft delete).
 * Confirms the deletion and provides audit trail information.
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class FolderDeleteResponse {

    /**
     * Unique identifier of the deleted folder (UUID v4).
     */
    private UUID folderId;

    /**
     * Timestamp when the folder was deleted.
     */
    private LocalDateTime deletedAt;

    /**
     * Status message confirming the deletion.
     */
    private String message;
}
