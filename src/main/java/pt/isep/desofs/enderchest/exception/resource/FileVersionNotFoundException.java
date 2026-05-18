package pt.isep.desofs.enderchest.exception.resource;

import java.util.UUID;

/**
 * Exception thrown when a file version is not found.
 *
 * This is used when attempting to access a specific version of a file
 * that does not exist in the database.
 *
 * @author Backend Architecture
 * @version 1.0
 */
public class FileVersionNotFoundException extends RuntimeException {

    public FileVersionNotFoundException(UUID versionId) {
        super(String.format("File version not found with ID: %s", versionId));
    }

    public FileVersionNotFoundException(String message) {
        super(message);
    }

    public FileVersionNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
