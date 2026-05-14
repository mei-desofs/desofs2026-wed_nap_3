package pt.isep.desofs.enderchest.exception.resource;

/**
 * Exception thrown when user's storage quota is exceeded during file upload.
 * 
 * This exception is thrown when:
 * - Attempting to upload a file that would exceed per-user storage quota
 * - User has reached their storage limit
 * 
 * Response: HTTP 413 Payload Too Large
 * 
 * Security: Does not expose actual quota values (prevents enumeration attacks)
 * 
 * @author Backend Architecture
 * @version 1.0
 */
public class StorageQuotaExceededException extends RuntimeException {
    
    /**
     * Create exception with user ID and storage info (for logging only).
     * 
     * @param userId The user ID that exceeded quota
     * @param currentUsage Current storage usage in bytes
     * @param quotaLimit Quota limit in bytes
     * @param fileSize Size of file attempting to upload
     */
    public StorageQuotaExceededException(String userId, long currentUsage, long quotaLimit, long fileSize) {
        super(String.format(
            "Storage quota exceeded: user=%s, current=%d bytes, quota=%d bytes, file=%d bytes",
            userId, currentUsage, quotaLimit, fileSize
        ));
    }
    
    /**
     * Create exception with custom message.
     * 
     * @param message Detailed error message
     */
    public StorageQuotaExceededException(String message) {
        super(message);
    }
}
