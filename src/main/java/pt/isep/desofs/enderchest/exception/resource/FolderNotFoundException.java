package pt.isep.desofs.enderchest.exception.resource;

import java.util.UUID;

/**
 * Exception thrown when a folder is not found or has been deleted.
 * 
 * Used when:
 * - Attempting to access a folder that doesn't exist
 * - Attempting to access a folder that was soft-deleted
 * - Attempting to list files in a non-existent folder
 * 
 * @author Backend Architecture
 * @version 1.0
 */
public class FolderNotFoundException extends RuntimeException {
    
    /**
     * Create exception with folder ID.
     * 
     * @param folderId The UUID of the folder that was not found
     */
    public FolderNotFoundException(UUID folderId) {
        super(String.format("Folder not found or has been deleted: %s", folderId));
    }
    
    /**
     * Create exception with custom message.
     * 
     * @param message Detailed error message
     */
    public FolderNotFoundException(String message) {
        super(message);
    }
}
