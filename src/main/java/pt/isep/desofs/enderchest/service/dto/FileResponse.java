package pt.isep.desofs.enderchest.service.dto;

import lombok.Getter;
import lombok.ToString;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import pt.isep.desofs.enderchest.entity.File;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * DTO for file retrieval response.
 * 
 * Returned when retrieving a file to provide metadata along with file content.
 * Contains both metadata for display and the actual file content.
 * 
 * Security considerations:
 * - File content is marked as @JsonIgnore when used in REST responses
 * - Use dedicated controller for file download with proper streaming
 * - Access control already validated in FileStorageService.retrieveFile()
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Getter
@ToString(exclude = "fileContent")
public class FileResponse {

    /**
     * Unique file identifier (UUID v4).
     */
    private UUID fileId;

    /**
     * Original filename as provided by uploader.
     */
    private String originalFileName;

    /**
     * SHA-256 hash of file contents (64 hex characters).
     */
    private String sha256Hash;

    /**
     * File size in bytes.
     */
    private Long fileSize;

    /**
     * MIME type (content type) detected via magic bytes.
     */
    private String mimeType;

    /**
     * Timestamp when the file was uploaded.
     * Formatted as ISO-8601 in JSON responses.
     */
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", timezone = "UTC")
    private LocalDateTime uploadedAt;

    /**
     * User ID who uploaded the file.
     */
    private String uploadedBy;

    /**
     * File content bytes.
     * NOT included in JSON responses by default (use controller streaming for downloads).
     */
    @JsonIgnore
    private byte[] fileContent;

    /**
     * Constructor from File entity.
     * 
     * @param file File entity with metadata
     * @param fileContent Raw file bytes (typically read from disk)
     */
    public FileResponse(File file, byte[] fileContent) {
        this.fileId = file.getId();
        this.originalFileName = file.getOriginalFileName();
        this.sha256Hash = file.getSha256Hash();
        this.fileSize = file.getFileSize();
        this.mimeType = file.getMimeType();
        this.uploadedAt = file.getUploadedAt();
        this.uploadedBy = file.getUploadedBy();
        this.fileContent = fileContent;
    }

    /**
     * Constructor with all fields (for testing).
     */
    public FileResponse(UUID fileId, String originalFileName, String sha256Hash,
                       Long fileSize, String mimeType, LocalDateTime uploadedAt,
                       String uploadedBy, byte[] fileContent) {
        this.fileId = fileId;
        this.originalFileName = originalFileName;
        this.sha256Hash = sha256Hash;
        this.fileSize = fileSize;
        this.mimeType = mimeType;
        this.uploadedAt = uploadedAt;
        this.uploadedBy = uploadedBy;
        this.fileContent = fileContent;
    }
}
