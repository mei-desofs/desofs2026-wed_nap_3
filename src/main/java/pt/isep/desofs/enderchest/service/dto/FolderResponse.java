package pt.isep.desofs.enderchest.service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.UUID;

/**
 * DTO for folder response.
 * 
 * Returned after successful folder creation or retrieval operations.
 * Contains essential folder metadata for client-side display and navigation.
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class FolderResponse {

    /**
     * Unique identifier of the folder (UUID v4).
     * Used to reference this folder in subsequent API calls.
     */
    private UUID folderId;

    /**
     * Name of the folder.
     * User-friendly display name for the folder.
     */
    private String folderName;

    /**
     * UUID of the parent folder (nullable).
     * Null indicates this is a root-level folder.
     */
    private UUID parentFolderId;

    /**
     * Count of child items (files or folders) directly contained in this folder.
     * Used for UI display and pagination purposes.
     */
    private Long childCount;

    /**
     * Whether this folder is active (not soft-deleted).
     */
    private Boolean isActive;
}
