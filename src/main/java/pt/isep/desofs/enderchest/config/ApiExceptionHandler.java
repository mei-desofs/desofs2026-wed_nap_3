package pt.isep.desofs.enderchest.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import pt.isep.desofs.enderchest.exception.resource.CircularReferenceFolderException;
import pt.isep.desofs.enderchest.exception.resource.FolderNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.InvalidFolderNameException;
import pt.isep.desofs.enderchest.exception.resource.StorageQuotaExceededException;
import pt.isep.desofs.enderchest.exception.security.FileUploadException;
import pt.isep.desofs.enderchest.exception.security.InvalidFileTypeException;
import pt.isep.desofs.enderchest.exception.security.PathTraversalAttemptException;
import pt.isep.desofs.enderchest.exception.security.RateLimitException;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Global exception handler for REST API controllers.
 *
 * Provides centralized error handling and standardized error responses across
 * all REST endpoints. Catches specific exceptions and converts them to
 * appropriate HTTP status codes with meaningful error messages.
 *
 * Features:
 * - Unified error response format
 * - Timestamp and request context tracking
 * - Validation error detail extraction
 * - Security exception handling
 * - Resource not found handling
 * - Logging for audit trail
 *
 * Error Response Format:
 * {
 *   "timestamp": "2024-01-15T10:50:00.000Z",
 *   "status": 400,
 *   "error": "Bad Request",
 *   "message": "Detailed error message",
 *   "path": "/api/v1/files/upload"
 * }
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Slf4j
@ControllerAdvice
public class ApiExceptionHandler {

    /**
     * Handle validation errors from request body validation.
     *
     * Catches @Valid validation failures and extracts field-level error details.
     * Returns 400 Bad Request with detailed validation error messages.
     *
     * @param ex MethodArgumentNotValidException containing validation errors
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {

        Map<String, Object> errors = new HashMap<>();
        errors.put("timestamp", LocalDateTime.now());
        errors.put("status", HttpStatus.BAD_REQUEST.value());
        errors.put("error", "Validation Error");

        // Extract field-level validation errors
        Map<String, String> fieldErrors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            fieldErrors.put(fieldName, errorMessage);
        });

        errors.put("fieldErrors", fieldErrors);
        errors.put("message", "Request validation failed");

        log.warn("Validation error: {}", fieldErrors);

        return ResponseEntity.badRequest().body(errors);
    }

    /**
     * Handle folder not found exceptions.
     *
     * Returns 404 Not Found when requested folder does not exist.
     *
     * @param ex FolderNotFoundException
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(FolderNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ResponseEntity<Map<String, Object>> handleFolderNotFound(
            FolderNotFoundException ex) {

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.NOT_FOUND.value());
        error.put("error", "Not Found");
        error.put("message", ex.getMessage());

        log.warn("Folder not found: {}", ex.getMessage());

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    /**
     * Handle invalid folder name exceptions.
     *
     * Returns 400 Bad Request when folder name is invalid (null, blank, or contains illegal characters).
     * This can occur during folder creation or renaming operations.
     *
     * @param ex InvalidFolderNameException
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(InvalidFolderNameException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<Map<String, Object>> handleInvalidFolderName(
            InvalidFolderNameException ex) {

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.BAD_REQUEST.value());
        error.put("error", "Bad Request");
        error.put("message", ex.getMessage());

        log.warn("Invalid folder name: {}", ex.getMessage());

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Handle circular reference folder exceptions.
     *
     * Returns 400 Bad Request when attempting to move a folder into one of its descendants,
     * which would create a circular reference and break the folder hierarchy.
     *
     * @param ex CircularReferenceFolderException
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(CircularReferenceFolderException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<Map<String, Object>> handleCircularReferenceFolder(
            CircularReferenceFolderException ex) {

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.BAD_REQUEST.value());
        error.put("error", "Bad Request");
        error.put("message", ex.getMessage());

        log.warn("Circular reference folder detected: {}", ex.getMessage());

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Handle file upload exceptions.
     *
     * Returns 400 Bad Request for general file upload failures.
     * Examples: Invalid file format, corrupt file, I/O errors.
     *
     * @param ex FileUploadException
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(FileUploadException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<Map<String, Object>> handleFileUploadException(
            FileUploadException ex) {

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.BAD_REQUEST.value());
        error.put("error", "File Upload Error");
        error.put("message", ex.getMessage());

        log.error("File upload error: {}", ex.getMessage(), ex);

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Handle invalid file type exceptions.
     *
     * Returns 415 Unsupported Media Type when uploaded file has invalid MIME type.
     * This indicates a security validation failure (T-06 Web Shell mitigation).
     *
     * @param ex InvalidFileTypeException
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(InvalidFileTypeException.class)
    @ResponseStatus(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
    public ResponseEntity<Map<String, Object>> handleInvalidFileType(
            InvalidFileTypeException ex) {

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.UNSUPPORTED_MEDIA_TYPE.value());
        error.put("error", "Unsupported Media Type");
        error.put("message", ex.getMessage());

        log.warn("Invalid file type detected: {}", ex.getMessage());

        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body(error);
    }

    /**
     * Handle path traversal attack exceptions.
     *
     * Returns 400 Bad Request when path traversal attack is detected in file operations.
     * This is a critical security violation (prevents directory traversal attacks).
     *
     * @param ex PathTraversalAttemptException
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(PathTraversalAttemptException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<Map<String, Object>> handlePathTraversalAttempt(
            PathTraversalAttemptException ex) {

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.BAD_REQUEST.value());
        error.put("error", "Invalid Request");
        error.put("message", "Invalid file path");

        log.error("Path traversal attempt detected: {}", ex.getMessage());

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Handle illegal argument exceptions.
     *
     * Returns 400 Bad Request for invalid arguments in API calls.
     * Examples: Null values, invalid UUID format, out-of-range values.
     *
     * @param ex IllegalArgumentException
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<Map<String, Object>> handleIllegalArgumentException(
            IllegalArgumentException ex) {

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.BAD_REQUEST.value());
        error.put("error", "Bad Request");
        error.put("message", ex.getMessage());

        log.warn("Invalid argument: {}", ex.getMessage());

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Handle storage quota exceeded exceptions.
     *
     * Returns 413 Payload Too Large when user has exceeded their storage quota.
     * This enforces SDR-NEW-07 (Storage Quota Enforcement).
     *
     * @param ex StorageQuotaExceededException
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(StorageQuotaExceededException.class)
    @ResponseStatus(HttpStatus.PAYLOAD_TOO_LARGE)
    public ResponseEntity<Map<String, Object>> handleStorageQuotaExceeded(
            StorageQuotaExceededException ex) {

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.PAYLOAD_TOO_LARGE.value());
        error.put("error", "Payload Too Large");
        error.put("message", "User storage quota exceeded");

        log.warn("Storage quota exceeded: {}", ex.getMessage());

        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(error);
    }

    /**
     * Handle rate limit exceptions.
     *
     * Returns 429 Too Many Requests when user exceeds rate limit.
     * This enforces SDR-10 (Rate Limiting).
     * Includes Retry-After header with suggested retry delay.
     *
     * @param ex RateLimitException
     * @return ResponseEntity with error details
     */
    @ExceptionHandler(RateLimitException.class)
    @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
    public ResponseEntity<Map<String, Object>> handleRateLimit(
            RateLimitException ex) {

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
        error.put("error", "Too Many Requests");
        error.put("message", "Rate limit exceeded. Please retry later");

        log.warn("Rate limit exceeded: {}", ex.getMessage());

        ResponseEntity<Map<String, Object>> response = ResponseEntity
                .status(HttpStatus.TOO_MANY_REQUESTS)
                .body(error);

        // Add Retry-After header if available
        if (ex.getRetryAfterSeconds() > 0) {
            response = ResponseEntity
                    .status(HttpStatus.TOO_MANY_REQUESTS)
                    .header("Retry-After", String.valueOf(ex.getRetryAfterSeconds()))
                    .body(error);
        }

        return response;
    }

    /**
     * Handle all other unhandled exceptions.
     *
     * Fallback handler for any unexpected exceptions not caught by specific handlers.
     * Returns 500 Internal Server Error.
     * Never exposes internal error details to client (security practice).
     *
     * @param ex Exception
     * @return ResponseEntity with generic error message
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<Map<String, Object>> handleGenericException(
            Exception ex) throws Exception {

        // Re-lançar AccessDeniedException para o Spring Security tratar com 403
        if (ex instanceof org.springframework.security.access.AccessDeniedException) {
            throw ex;
        }

        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        error.put("error", "Internal Server Error");
        error.put("message", "An unexpected error occurred");

        log.error("Unexpected error:", ex);

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}
