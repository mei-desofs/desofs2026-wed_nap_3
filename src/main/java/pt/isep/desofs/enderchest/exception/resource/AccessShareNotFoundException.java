package pt.isep.desofs.enderchest.exception.resource;

import java.util.UUID;

/**
 * Exception thrown when an access share is not found.
 *
 * This is used when attempting to revoke, retrieve, or modify an
 * access share record that does not exist in the database.
 *
 * @author Backend Architecture
 * @version 1.0
 */
public class AccessShareNotFoundException extends RuntimeException {

    public AccessShareNotFoundException(UUID shareId) {
        super(String.format("Access share not found with ID: %s", shareId));
    }

    public AccessShareNotFoundException(String message) {
        super(message);
    }

    public AccessShareNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
