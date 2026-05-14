package pt.isep.desofs.enderchest.service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * DTO for file upload response.
 * 
 * Returned after successful file upload to confirm the operation and provide
 * essential metadata to the client including file ID, hash, size, and timestamp.
 * 
 * This response is sent immediately after successful database persistence
 * (before file indexing or further processing), ensuring sub-100ms response times.
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class UploadResponse {

    /**
     * Unique file identifier (UUID v4).
     * Can be used to retrieve or manage the file later.
     */
    private UUID fileId;

    /**
     * SHA-256 hash of file contents (64 hex characters).
     * Can be used for integrity verification and deduplication checks.
     * Immutable after upload.
     */
    private String sha256Hash;

    /**
     * File size in bytes.
     * Useful for client-side verification and quota tracking.
     */
    private Long fileSize;

    /**
     * Timestamp when the file was uploaded.
     * Formatted as ISO-8601 in JSON responses.
     */
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", timezone = "UTC")
    private LocalDateTime uploadedAt;

    /**
     * MIME type (content type) detected via magic bytes.
     * Examples: "application/pdf", "image/jpeg", "text/plain"
     */
    private String mimeType;
}
