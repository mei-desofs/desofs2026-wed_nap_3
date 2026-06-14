package pt.isep.desofs.enderchest.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import pt.isep.desofs.enderchest.exception.security.FileUploadException;
import pt.isep.desofs.enderchest.exception.security.InvalidFileTypeException;
import pt.isep.desofs.enderchest.exception.security.PathTraversalAttemptException;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GlobalSecurityExceptionHandler — information disclosure prevention tests")
class GlobalSecurityExceptionHandlerTest {

    private GlobalSecurityExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new GlobalSecurityExceptionHandler();
    }

    // ── FileUploadException ───────────────────────────────────────────────────

    @Test
    @DisplayName("InvalidFileTypeException: returns 400 and does not expose MIME type to client")
    void invalidFileType_returns400_mimeTypeNotExposed() {
        // InvalidFileTypeException(String detectedType, String allowedTypes)
        FileUploadException ex = new InvalidFileTypeException("application/x-msdownload", "image/jpeg,application/pdf");

        ResponseEntity<String> response = handler.handleFileUploadSecurityException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().contains("application/x-msdownload"),
                "Response must not expose the detected MIME type to the client");
    }

    @Test
    @DisplayName("PathTraversalAttemptException: returns 400 and generic message")
    void pathTraversal_returns400_genericMessage() {
        // PathTraversalAttemptException has no-arg constructor
        FileUploadException ex = new PathTraversalAttemptException();

        ResponseEntity<String> response = handler.handleFileUploadSecurityException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().isBlank());
    }

    @Test
    @DisplayName("FileUploadException: response body does not contain internal exception message")
    void fileUploadException_responseBodyIsGeneric() {
        FileUploadException ex = new FileUploadException("Internal detail: quota exceeded for user abc-123");

        ResponseEntity<String> response = handler.handleFileUploadSecurityException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertFalse(response.getBody().contains("abc-123"),
                "Response must not expose internal user identifiers");
    }

    // ── AccessDeniedException ─────────────────────────────────────────────────

    @Test
    @DisplayName("AccessDeniedException: returns 403 Forbidden")
    void accessDeniedException_returns403() {
        AccessDeniedException ex = new AccessDeniedException("Access is denied");

        ResponseEntity<String> response = handler.handleAccessDeniedException(ex);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    @DisplayName("AccessDeniedException: response body does not expose internal role details")
    void accessDeniedException_roleNotExposed() {
        AccessDeniedException ex = new AccessDeniedException("ROLE_VIEWER cannot access ROLE_ADMIN endpoint");

        ResponseEntity<String> response = handler.handleAccessDeniedException(ex);

        assertFalse(response.getBody().contains("ROLE_VIEWER"),
                "Internal role names must not be exposed in the response body");
        assertFalse(response.getBody().contains("ROLE_ADMIN"),
                "Internal role names must not be exposed in the response body");
    }

    // ── Generic Exception ─────────────────────────────────────────────────────

    @Test
    @DisplayName("RuntimeException: returns 500 and does not expose stack trace details")
    void genericException_returns500_stackTraceNotExposed() {
        Exception ex = new RuntimeException("DB connection failed: jdbc:postgresql://prod-db:5432/secrets");

        ResponseEntity<String> response = handler.handleGenericException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertFalse(response.getBody().contains("jdbc:postgresql"),
                "Database connection strings must not be exposed");
        assertFalse(response.getBody().contains("RuntimeException"),
                "Exception class names must not be exposed");
    }

    @Test
    @DisplayName("NullPointerException: returns 500 and does not expose class or line number")
    void nullPointerException_returns500_noSourceDetails() {
        NullPointerException ex = new NullPointerException("null at FileController.java:47");

        ResponseEntity<String> response = handler.handleGenericException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertFalse(response.getBody().contains("FileController"),
                "Source file names must not be exposed");
    }
}
