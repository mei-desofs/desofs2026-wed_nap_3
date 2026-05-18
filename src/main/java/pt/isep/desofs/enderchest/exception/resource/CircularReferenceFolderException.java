package pt.isep.desofs.enderchest.exception.resource;

import java.util.UUID;

/**
 * Exception thrown when a folder move operation would create a circular reference.
 *
 * This is used to prevent moving a folder into one of its descendants,
 * which would create a circular parent-child relationship and break the hierarchy.
 *
 * @author Backend Architecture
 * @version 1.0
 */
public class CircularReferenceFolderException extends RuntimeException {

    public CircularReferenceFolderException(UUID folderId, UUID newParentId) {
        super(String.format("Moving folder %s to parent %s would create a circular reference", folderId, newParentId));
    }

    public CircularReferenceFolderException(String message) {
        super(message);
    }

    public CircularReferenceFolderException(String message, Throwable cause) {
        super(message, cause);
    }
}
