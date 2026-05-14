package pt.isep.desofs.enderchest.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import pt.isep.desofs.enderchest.entity.AuditLog;
import pt.isep.desofs.enderchest.repository.AuditLogRepository;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Service for managing audit logs.
 * 
 * Implements FR-08 (Audit Logging) and SDR-NEW-12 (Comprehensive Audit Trail).
 * Provides audit logging methods for all significant system actions (file operations, 
 * folder operations, sharing actions) without storing sensitive data.
 * 
 * All logging methods are @Transactional(readOnly=false) to ensure database persistence.
 * Each method builds a details JSON with relevant metadata (never including passwords/tokens).
 * 
 * Performance: Async logging via separate thread would improve latency, but currently
 * synchronous to ensure audit log completion before response. Consider async for high-volume.
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Extract client IP address from HTTP request.
     * Handles X-Forwarded-For header for reverse proxy scenarios.
     * 
     * @return IP address or "unknown" if unavailable
     */
    private String getClientIpAddress() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return "unknown";
            }
            HttpServletRequest request = attrs.getRequest();
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                return xForwardedFor.split(",")[0].trim();
            }
            return request.getRemoteAddr();
        } catch (Exception e) {
            log.debug("Failed to extract client IP address", e);
            return "unknown";
        }
    }

    /**
     * Convert details map to JSON string (never including sensitive data).
     * Gracefully handles serialization failures.
     * 
     * @param details Map of details to serialize
     * @return JSON string or null if map is empty
     */
    private String detailsToJson(Map<String, Object> details) {
        if (details == null || details.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(details);
        } catch (Exception e) {
            log.warn("Failed to serialize audit details", e);
            return null;
        }
    }

    /**
     * Log file upload action.
     * 
     * Records: user who uploaded, file ID, file size, original file name, folder ID (if applicable).
     * Does NOT record: file content, MIME type, or hash (for security).
     * 
     * @param userId User ID who uploaded the file
     * @param fileId File ID of uploaded file
     * @param fileSize Size in bytes
     * @param fileName Original file name
     * @param folderId Optional folder ID (null for root)
     */
    @Transactional(readOnly = false)
    public void logFileUpload(String userId, UUID fileId, long fileSize, String fileName, UUID folderId) {
        try {
            Map<String, Object> details = new HashMap<>();
            details.put("fileName", fileName);
            details.put("fileSize", fileSize);
            if (folderId != null) {
                details.put("folderId", folderId.toString());
            }

            AuditLog auditEntry = new AuditLog(
                AuditLog.Action.FILE_UPLOAD,
                userId,
                AuditLog.ResourceType.FILE,
                fileId,
                detailsToJson(details),
                getClientIpAddress()
            );
            auditLogRepository.save(auditEntry);
            log.info("Logged file upload: userId={}, fileId={}, fileName={}", userId, fileId, fileName);
        } catch (Exception e) {
            log.error("Failed to log file upload", e);
            // Don't throw - audit logging failure should not break file upload
        }
    }

    /**
     * Log file download action.
     * 
     * Records: user who downloaded, file ID, file name.
     * Does NOT record: file content or destination.
     * 
     * @param userId User ID who downloaded the file
     * @param fileId File ID of downloaded file
     * @param fileName Original file name
     */
    @Transactional(readOnly = false)
    public void logFileDownload(String userId, UUID fileId, String fileName) {
        try {
            Map<String, Object> details = new HashMap<>();
            details.put("fileName", fileName);

            AuditLog auditEntry = new AuditLog(
                AuditLog.Action.FILE_DOWNLOAD,
                userId,
                AuditLog.ResourceType.FILE,
                fileId,
                detailsToJson(details),
                getClientIpAddress()
            );
            auditLogRepository.save(auditEntry);
            log.info("Logged file download: userId={}, fileId={}", userId, fileId);
        } catch (Exception e) {
            log.error("Failed to log file download", e);
        }
    }

    /**
     * Log file deletion action.
     * 
     * Records: user who deleted, file ID, file name.
     * Does NOT record: storage location or backup details.
     * 
     * @param userId User ID who deleted the file
     * @param fileId File ID of deleted file
     * @param fileName Original file name
     */
    @Transactional(readOnly = false)
    public void logFileDelete(String userId, UUID fileId, String fileName) {
        try {
            Map<String, Object> details = new HashMap<>();
            details.put("fileName", fileName);

            AuditLog auditEntry = new AuditLog(
                AuditLog.Action.FILE_DELETE,
                userId,
                AuditLog.ResourceType.FILE,
                fileId,
                detailsToJson(details),
                getClientIpAddress()
            );
            auditLogRepository.save(auditEntry);
            log.info("Logged file deletion: userId={}, fileId={}", userId, fileId);
        } catch (Exception e) {
            log.error("Failed to log file deletion", e);
        }
    }

    /**
     * Log folder creation action.
     * 
     * Records: user who created, folder ID, folder name, parent folder ID (if applicable).
     * 
     * @param userId User ID who created the folder
     * @param folderId Folder ID of created folder
     * @param folderName Folder name
     * @param parentFolderId Optional parent folder ID (null for root)
     */
    @Transactional(readOnly = false)
    public void logFolderCreate(String userId, UUID folderId, String folderName, UUID parentFolderId) {
        try {
            Map<String, Object> details = new HashMap<>();
            details.put("folderName", folderName);
            if (parentFolderId != null) {
                details.put("parentFolderId", parentFolderId.toString());
            }

            AuditLog auditEntry = new AuditLog(
                AuditLog.Action.FOLDER_CREATE,
                userId,
                AuditLog.ResourceType.FOLDER,
                folderId,
                detailsToJson(details),
                getClientIpAddress()
            );
            auditLogRepository.save(auditEntry);
            log.info("Logged folder creation: userId={}, folderId={}, folderName={}", userId, folderId, folderName);
        } catch (Exception e) {
            log.error("Failed to log folder creation", e);
        }
    }

    /**
     * Log folder deletion action.
     * 
     * Records: user who deleted, folder ID, folder name.
     * Does NOT record: recursive deletion details.
     * 
     * @param userId User ID who deleted the folder
     * @param folderId Folder ID of deleted folder
     * @param folderName Folder name
     */
    @Transactional(readOnly = false)
    public void logFolderDelete(String userId, UUID folderId, String folderName) {
        try {
            Map<String, Object> details = new HashMap<>();
            details.put("folderName", folderName);

            AuditLog auditEntry = new AuditLog(
                AuditLog.Action.FOLDER_DELETE,
                userId,
                AuditLog.ResourceType.FOLDER,
                folderId,
                detailsToJson(details),
                getClientIpAddress()
            );
            auditLogRepository.save(auditEntry);
            log.info("Logged folder deletion: userId={}, folderId={}", userId, folderId);
        } catch (Exception e) {
            log.error("Failed to log folder deletion", e);
        }
    }

    /**
     * Log share grant action (permission granted to another user).
     * 
     * Records: user who granted, resource ID, resource type, user who received access, role granted.
     * Does NOT record: sensitive user information.
     * 
     * @param userId User ID who granted the share
     * @param resourceId Resource ID (file or folder) being shared
     * @param resourceType Type of resource (FILE or FOLDER)
     * @param grantedToUserId User ID who received access
     * @param role Role granted (e.g., VIEWER, EDITOR)
     */
    @Transactional(readOnly = false)
    public void logShareGrant(String userId, UUID resourceId, String resourceType, 
                            String grantedToUserId, String role) {
        try {
            Map<String, Object> details = new HashMap<>();
            details.put("grantedTo", grantedToUserId);
            details.put("role", role);

            AuditLog auditEntry = new AuditLog(
                AuditLog.Action.SHARE_GRANT,
                userId,
                resourceType,
                resourceId,
                detailsToJson(details),
                getClientIpAddress()
            );
            auditLogRepository.save(auditEntry);
            log.info("Logged share grant: userId={}, resourceId={}, grantedTo={}, role={}", 
                    userId, resourceId, grantedToUserId, role);
        } catch (Exception e) {
            log.error("Failed to log share grant", e);
        }
    }

    /**
     * Log share revoke action (permission removed from another user).
     * 
     * Records: user who revoked, resource ID, resource type, user who lost access, role revoked.
     * Does NOT record: sensitive user information.
     * 
     * @param userId User ID who revoked the share
     * @param resourceId Resource ID (file or folder)
     * @param resourceType Type of resource (FILE or FOLDER)
     * @param revokedFromUserId User ID who lost access
     * @param role Role revoked (e.g., VIEWER, EDITOR)
     */
    @Transactional(readOnly = false)
    public void logShareRevoke(String userId, UUID resourceId, String resourceType, 
                              String revokedFromUserId, String role) {
        try {
            Map<String, Object> details = new HashMap<>();
            details.put("revokedFrom", revokedFromUserId);
            details.put("role", role);

            AuditLog auditEntry = new AuditLog(
                AuditLog.Action.SHARE_REVOKE,
                userId,
                resourceType,
                resourceId,
                detailsToJson(details),
                getClientIpAddress()
            );
            auditLogRepository.save(auditEntry);
            log.info("Logged share revoke: userId={}, resourceId={}, revokedFrom={}, role={}", 
                    userId, resourceId, revokedFromUserId, role);
        } catch (Exception e) {
            log.error("Failed to log share revoke", e);
        }
    }

    /**
     * Retrieve recent audit logs (admin-only endpoint).
     * 
     * Returns most recent entries across all users for monitoring.
     * Use with caution - only expose to authorized admins.
     * 
     * @param limit Maximum number of entries to return
     * @return List of recent audit logs, newest first
     */
    @Transactional(readOnly = true)
    public List<AuditLog> getRecentLogs(int limit) {
        try {
            Pageable pageable = PageRequest.of(0, Math.min(limit, 100)); // Cap at 100
            Page<AuditLog> page = auditLogRepository.findAll(pageable);
            log.debug("Retrieved {} recent audit logs", page.getNumberOfElements());
            return page.getContent();
        } catch (Exception e) {
            log.error("Failed to retrieve recent audit logs", e);
            return List.of();
        }
    }

    /**
     * Retrieve audit logs for a specific user (admin-only endpoint).
     * 
     * Returns all actions performed by or on behalf of a specific user.
     * Use with caution - only expose to authorized admins.
     * 
     * @param userId User ID to retrieve logs for
     * @param limit Maximum number of entries to return
     * @return List of audit logs for the user, newest first
     */
    @Transactional(readOnly = true)
    public List<AuditLog> getLogsForUser(String userId, int limit) {
        try {
            Pageable pageable = PageRequest.of(0, Math.min(limit, 100)); // Cap at 100
            Page<AuditLog> page = auditLogRepository.findByUserId(userId, pageable);
            log.debug("Retrieved {} audit logs for user {}", page.getNumberOfElements(), userId);
            return page.getContent();
        } catch (Exception e) {
            log.error("Failed to retrieve audit logs for user {}", userId, e);
            return List.of();
        }
    }

    /**
     * Retrieve audit logs for a specific resource (admin-only endpoint).
     * 
     * Shows complete audit history of a file/folder/share.
     * Use with caution - only expose to authorized admins.
     * 
     * @param resourceId Resource UUID to retrieve logs for
     * @return List of audit logs for the resource, newest first
     */
    @Transactional(readOnly = true)
    public List<AuditLog> getLogsForResource(UUID resourceId) {
        try {
            List<AuditLog> logs = auditLogRepository.findByResourceId(resourceId);
            log.debug("Retrieved {} audit logs for resource {}", logs.size(), resourceId);
            return logs;
        } catch (Exception e) {
            log.error("Failed to retrieve audit logs for resource {}", resourceId, e);
            return List.of();
        }
    }
}
