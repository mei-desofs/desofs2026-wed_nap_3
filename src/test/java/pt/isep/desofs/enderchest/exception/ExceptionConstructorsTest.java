package pt.isep.desofs.enderchest.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import pt.isep.desofs.enderchest.exception.resource.AccessShareNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.CircularReferenceFolderException;
import pt.isep.desofs.enderchest.exception.resource.DuplicateAccessShareException;
import pt.isep.desofs.enderchest.exception.resource.FileNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.FileVersionNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.FolderNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.InvalidFolderNameException;
import pt.isep.desofs.enderchest.exception.resource.StorageQuotaExceededException;
import pt.isep.desofs.enderchest.exception.resource.UserNotFoundException;
import pt.isep.desofs.enderchest.exception.security.FileAccessDeniedException;
import pt.isep.desofs.enderchest.exception.security.FileUploadException;
import pt.isep.desofs.enderchest.exception.security.InvalidFileTypeException;
import pt.isep.desofs.enderchest.exception.security.PathTraversalAttemptException;
import pt.isep.desofs.enderchest.exception.security.RateLimitException;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Exception Constructors Unit Tests")
class ExceptionConstructorsTest {

    @Test
    @DisplayName("RateLimitException: userId/retryAfter constructor and message constructor")
    void rateLimitException() {
        RateLimitException withRetry = new RateLimitException("user-1", 45);
        assertEquals("user-1", withRetry.getUserId());
        assertEquals(45, withRetry.getRetryAfterSeconds());
        assertTrue(withRetry.getMessage().contains("user-1"));

        RateLimitException msg = new RateLimitException("custom");
        assertNull(msg.getUserId());
        assertEquals(0, msg.getRetryAfterSeconds());
        assertEquals("custom", msg.getMessage());
    }

    @Test
    @DisplayName("FileAccessDeniedException: all constructors")
    void fileAccessDenied() {
        UUID fileId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        assertTrue(new FileAccessDeniedException(fileId, userId).getMessage().contains(fileId.toString()));
        assertEquals("denied", new FileAccessDeniedException("denied").getMessage());
        FileAccessDeniedException withCause = new FileAccessDeniedException("denied", new RuntimeException("x"));
        assertNotNull(withCause.getCause());
    }

    @Test
    @DisplayName("FileUploadException, PathTraversalAttemptException, InvalidFileTypeException")
    void uploadExceptions() {
        assertEquals("upload", new FileUploadException("upload").getMessage());
        assertTrue(new PathTraversalAttemptException().getMessage().contains("Path Traversal"));
        assertTrue(new InvalidFileTypeException("application/x-php", "image/png").getMessage().contains("x-php"));
    }

    @Test
    @DisplayName("StorageQuotaExceededException: both constructors")
    void storageQuota() {
        StorageQuotaExceededException detailed =
                new StorageQuotaExceededException("user-1", 10, 20, 15);
        assertTrue(detailed.getMessage().contains("user-1"));
        assertEquals("quota", new StorageQuotaExceededException("quota").getMessage());
    }

    @Test
    @DisplayName("FileNotFoundException: all constructors")
    void fileNotFound() {
        UUID id = UUID.randomUUID();
        assertTrue(new FileNotFoundException(id).getMessage().contains(id.toString()));
        assertEquals("nope", new FileNotFoundException("nope").getMessage());
        assertNotNull(new FileNotFoundException("nope", new RuntimeException()).getCause());
    }

    @Test
    @DisplayName("FolderNotFoundException: both constructors")
    void folderNotFound() {
        UUID id = UUID.randomUUID();
        assertTrue(new FolderNotFoundException(id).getMessage().contains(id.toString()));
        assertEquals("gone", new FolderNotFoundException("gone").getMessage());
    }

    @Test
    @DisplayName("InvalidFolderNameException: all constructors")
    void invalidFolderName() {
        assertEquals("bad", new InvalidFolderNameException("bad").getMessage());
        assertNotNull(new InvalidFolderNameException("bad", new RuntimeException()).getCause());
        assertNotNull(new InvalidFolderNameException().getMessage());
    }

    @Test
    @DisplayName("CircularReferenceFolderException: all constructors")
    void circularReference() {
        UUID a = UUID.randomUUID();
        UUID b = UUID.randomUUID();
        assertTrue(new CircularReferenceFolderException(a, b).getMessage().contains(a.toString()));
        assertEquals("circ", new CircularReferenceFolderException("circ").getMessage());
        assertNotNull(new CircularReferenceFolderException("circ", new RuntimeException()).getCause());
    }

    @Test
    @DisplayName("FileVersionNotFoundException: all constructors")
    void fileVersionNotFound() {
        UUID id = UUID.randomUUID();
        assertTrue(new FileVersionNotFoundException(id).getMessage().contains(id.toString()));
        assertEquals("v", new FileVersionNotFoundException("v").getMessage());
        assertNotNull(new FileVersionNotFoundException("v", new RuntimeException()).getCause());
    }

    @Test
    @DisplayName("UserNotFoundException: all constructors")
    void userNotFound() {
        UUID id = UUID.randomUUID();
        assertTrue(new UserNotFoundException(id).getMessage().contains(id.toString()));
        assertEquals("u", new UserNotFoundException("u").getMessage());
        assertNotNull(new UserNotFoundException("u", new RuntimeException()).getCause());
    }

    @Test
    @DisplayName("AccessShareNotFoundException: all constructors")
    void accessShareNotFound() {
        UUID id = UUID.randomUUID();
        assertTrue(new AccessShareNotFoundException(id).getMessage().contains(id.toString()));
        assertEquals("s", new AccessShareNotFoundException("s").getMessage());
        assertNotNull(new AccessShareNotFoundException("s", new RuntimeException()).getCause());
    }

    @Test
    @DisplayName("DuplicateAccessShareException: all constructors")
    void duplicateAccessShare() {
        UUID resource = UUID.randomUUID();
        UUID user = UUID.randomUUID();
        assertTrue(new DuplicateAccessShareException(resource, user).getMessage().contains(resource.toString()));
        assertEquals("dup", new DuplicateAccessShareException("dup").getMessage());
        assertNotNull(new DuplicateAccessShareException("dup", new RuntimeException()).getCause());
    }
}
