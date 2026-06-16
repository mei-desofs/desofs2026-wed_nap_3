package pt.isep.desofs.enderchest.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import pt.isep.desofs.enderchest.exception.resource.CircularReferenceFolderException;
import pt.isep.desofs.enderchest.exception.resource.FileNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.FolderNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.InvalidFolderNameException;
import pt.isep.desofs.enderchest.exception.resource.StorageQuotaExceededException;
import pt.isep.desofs.enderchest.exception.security.FileAccessDeniedException;
import pt.isep.desofs.enderchest.exception.security.FileUploadException;
import pt.isep.desofs.enderchest.exception.security.InvalidFileTypeException;
import pt.isep.desofs.enderchest.exception.security.PathTraversalAttemptException;
import pt.isep.desofs.enderchest.exception.security.RateLimitException;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ApiExceptionHandler Unit Tests")
class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    @Test
    @DisplayName("handleValidationExceptions: returns 400 with field errors")
    void handleValidationExceptions_returnsBadRequest() {
        BindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "obj");
        bindingResult.addError(new FieldError("obj", "folderName", "must not be blank"));
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(null, bindingResult);

        ResponseEntity<Map<String, Object>> response = handler.handleValidationExceptions(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        @SuppressWarnings("unchecked")
        Map<String, String> fieldErrors = (Map<String, String>) response.getBody().get("fieldErrors");
        assertEquals("must not be blank", fieldErrors.get("folderName"));
    }

    @Test
    @DisplayName("handleFolderNotFound: returns 404")
    void handleFolderNotFound_returnsNotFound() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleFolderNotFound(new FolderNotFoundException(UUID.randomUUID()));
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(404, response.getBody().get("status"));
    }

    @Test
    @DisplayName("handleInvalidFolderName: returns 400")
    void handleInvalidFolderName_returnsBadRequest() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleInvalidFolderName(new InvalidFolderNameException());
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    @DisplayName("handleCircularReferenceFolder: returns 400")
    void handleCircularReferenceFolder_returnsBadRequest() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleCircularReferenceFolder(
                        new CircularReferenceFolderException(UUID.randomUUID(), UUID.randomUUID()));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    @DisplayName("handleFileUploadException: returns 400")
    void handleFileUploadException_returnsBadRequest() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleFileUploadException(new FileUploadException("upload failed"));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    @DisplayName("handleInvalidFileType: returns 415")
    void handleInvalidFileType_returnsUnsupportedMediaType() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleInvalidFileType(new InvalidFileTypeException("application/x-php", "image/png"));
        assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE, response.getStatusCode());
    }

    @Test
    @DisplayName("handlePathTraversalAttempt: returns 400 with generic message")
    void handlePathTraversalAttempt_returnsBadRequest() {
        ResponseEntity<Map<String, Object>> response =
                handler.handlePathTraversalAttempt(new PathTraversalAttemptException());
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Invalid file path", response.getBody().get("message"));
    }

    @Test
    @DisplayName("handleIllegalArgumentException: returns 400")
    void handleIllegalArgumentException_returnsBadRequest() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleIllegalArgumentException(new IllegalArgumentException("bad arg"));
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    @DisplayName("handleStorageQuotaExceeded: returns 413")
    void handleStorageQuotaExceeded_returnsPayloadTooLarge() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleStorageQuotaExceeded(new StorageQuotaExceededException("quota exceeded"));
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
    }

    @Test
    @DisplayName("handleRateLimit: returns 429 with Retry-After header when retry seconds present")
    void handleRateLimit_withRetryAfter_setsHeader() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleRateLimit(new RateLimitException("user-1", 30));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
        assertEquals("30", response.getHeaders().getFirst("Retry-After"));
    }

    @Test
    @DisplayName("handleRateLimit: returns 429 without header when retry seconds is zero")
    void handleRateLimit_withoutRetryAfter_noHeader() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleRateLimit(new RateLimitException("no retry"));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
        assertNull(response.getHeaders().getFirst("Retry-After"));
    }

    @Test
    @DisplayName("handleFileNotFound: returns 404")
    void handleFileNotFound_returnsNotFound() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleFileNotFound(new FileNotFoundException(UUID.randomUUID()));
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    @DisplayName("handleFileAccessDenied: returns 403 with generic message")
    void handleFileAccessDenied_returnsForbidden() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleFileAccessDenied(new FileAccessDeniedException("denied"));
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Access denied", response.getBody().get("message"));
    }

    @Test
    @DisplayName("handleGenericException: returns 500 for generic exception")
    void handleGenericException_returnsInternalServerError() throws Exception {
        ResponseEntity<Map<String, Object>> response =
                handler.handleGenericException(new RuntimeException("boom"));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("An unexpected error occurred", response.getBody().get("message"));
    }

    @Test
    @DisplayName("handleGenericException: rethrows Spring AccessDeniedException")
    void handleGenericException_rethrowsAccessDenied() {
        org.springframework.security.access.AccessDeniedException ade =
                new org.springframework.security.access.AccessDeniedException("nope");
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> handler.handleGenericException(ade));
    }
}
