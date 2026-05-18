package pt.isep.desofs.enderchest.exception.resource;

import java.util.UUID;

/**
 * Exception thrown when a file resource is not found.
 *
 * This is used throughout the application when attempting to access,
 * modify, or delete a file that does not exist in the database.
 *
 * @author Backend Architecture
 * @version 1.0
 */
public class FileNotFoundException extends RuntimeException {

    public FileNotFoundException(UUID fileId) {
        super(String.format("File not found with ID: %s", fileId));
    }

    public FileNotFoundException(String message) {
        super(message);
    }

    public FileNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
