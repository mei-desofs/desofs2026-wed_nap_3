package pt.isep.desofs.enderchest.exception.resource;

import java.util.UUID;

/**
 * Exception thrown when a user resource is not found.
 *
 * This is used when attempting to access, verify, or retrieve user
 * information that does not exist in the database.
 *
 * @author Backend Architecture
 * @version 1.0
 */
public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException(UUID userId) {
        super(String.format("User not found with ID: %s", userId));
    }

    public UserNotFoundException(String message) {
        super(message);
    }

    public UserNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
