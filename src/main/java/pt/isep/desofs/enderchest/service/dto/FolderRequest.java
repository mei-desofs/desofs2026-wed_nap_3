package pt.isep.desofs.enderchest.service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.UUID;

/**
 * DTO for folder creation request.
 * 
 * Contains the necessary information to create a new folder within the file system.
 * The parentFolderId is optional - null indicates a root-level folder.
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class FolderRequest {

    /**
     * Name of the folder to create.
     * Must not be blank. Used for user-friendly display.
     */
    @NotBlank(message = "Folder name must not be blank")
    private String folderName;

    /**
     * UUID of the parent folder (optional).
     * If null, the folder is created at the root level.
     * If provided, must reference an existing folder owned by the same user.
     */
    private UUID parentFolderId;
}
