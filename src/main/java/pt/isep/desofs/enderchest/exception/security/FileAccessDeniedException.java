package pt.isep.desofs.enderchest.exception.security;

import java.util.UUID;

/**
 * Exception thrown when a user lacks permission to access a file.
 *
 * This is used in IDOR (Insecure Direct Object Reference) prevention
 * to indicate that a user is trying to access a file they don't own
 * and don't have shared access to.
 *
 * @author Backend Architecture
 * @version 1.0
 */
public class FileAccessDeniedException extends RuntimeException {

    public FileAccessDeniedException(UUID fileId, UUID userId) {
        super(String.format("Access denied to file: %s for user: %s", fileId, userId));
    }

    public FileAccessDeniedException(String message) {
        super(message);
    }

    public FileAccessDeniedException(String message, Throwable cause) {
        super(message, cause);
    }
}
