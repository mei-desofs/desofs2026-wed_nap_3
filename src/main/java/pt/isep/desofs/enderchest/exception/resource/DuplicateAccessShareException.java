package pt.isep.desofs.enderchest.exception.resource;

import java.util.UUID;

/**
 * Exception thrown when attempting to create a duplicate access share.
 *
 * This is used when a user attempts to grant access to a resource
 * that has already been shared with the same user.
 *
 * @author Backend Architecture
 * @version 1.0
 */
public class DuplicateAccessShareException extends RuntimeException {

    public DuplicateAccessShareException(UUID resourceId, UUID userId) {
        super(String.format("Access share already exists for resource: %s and user: %s", resourceId, userId));
    }

    public DuplicateAccessShareException(String message) {
        super(message);
    }

    public DuplicateAccessShareException(String message, Throwable cause) {
        super(message, cause);
    }
}
