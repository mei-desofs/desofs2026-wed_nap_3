package pt.isep.desofs.enderchest.exception.resource;

/**
 * Exception thrown when a folder name is invalid.
 *
 * This is used when attempting to create or rename a folder with
 * an invalid name (null, blank, or containing illegal characters).
 *
 * @author Backend Architecture
 * @version 1.0
 */
public class InvalidFolderNameException extends RuntimeException {

    public InvalidFolderNameException(String message) {
        super(message);
    }

    public InvalidFolderNameException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidFolderNameException() {
        super("Folder name is invalid (null, blank, or contains illegal characters)");
    }
}
