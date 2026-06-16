package pt.isep.desofs.enderchest.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import pt.isep.desofs.enderchest.entity.AuditLog;
import pt.isep.desofs.enderchest.repository.AuditLogRepository;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuditLogService Unit Tests")
class AuditLogServiceTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @InjectMocks
    private AuditLogService auditLogService;

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    // ── logFileUpload ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("logFileUpload: persists file upload with forwarded IP and folder details")
    void logFileUpload_withForwardedForAndFolder_savesAuditLog() {
        UUID fileId = UUID.randomUUID();
        UUID folderId = UUID.randomUUID();
        setRequestWithForwardedFor("203.0.113.10, 10.0.0.1", "198.51.100.5");

        auditLogService.logFileUpload("user-1", fileId, 1234L, "report.pdf", folderId);

        AuditLog saved = captureSavedAuditLog();
        assertEquals(AuditLog.Action.FILE_UPLOAD, saved.getAction());
        assertEquals("user-1", saved.getUserId());
        assertEquals(AuditLog.ResourceType.FILE, saved.getResourceType());
        assertEquals(fileId, saved.getResourceId());
        assertEquals("203.0.113.10", saved.getIpAddress());
        assertTrue(saved.getDetails().contains("\"fileName\":\"report.pdf\""));
        assertTrue(saved.getDetails().contains("\"fileSize\":1234"));
        assertTrue(saved.getDetails().contains(folderId.toString()));
    }

    @Test
    @DisplayName("logFileUpload: persists upload without folder using remote address")
    void logFileUpload_withoutFolder_usesRemoteAddr() {
        UUID fileId = UUID.randomUUID();
        setRequest(null, "198.51.100.6");

        auditLogService.logFileUpload("user-1", fileId, 10L, "root.txt", null);

        AuditLog saved = captureSavedAuditLog();
        assertEquals("198.51.100.6", saved.getIpAddress());
        assertFalse(saved.getDetails().contains("folderId"));
    }

    @Test
    @DisplayName("logFileUpload: repository exception is swallowed")
    void logFileUpload_repositoryThrows_doesNotThrow() {
        when(auditLogRepository.save(any())).thenThrow(new RuntimeException("database down"));

        assertDoesNotThrow(() -> auditLogService.logFileUpload("user-1", UUID.randomUUID(), 1L, "file.txt", null));
        verify(auditLogRepository).save(any());
    }

    // ── logFileDownload ────────────────────────────────────────────────────────

    @Test
    @DisplayName("logFileDownload: persists file download with unknown IP when no request exists")
    void logFileDownload_noRequest_savesUnknownIp() {
        UUID fileId = UUID.randomUUID();
        RequestContextHolder.resetRequestAttributes();

        auditLogService.logFileDownload("user-2", fileId, "data.csv");

        AuditLog saved = captureSavedAuditLog();
        assertEquals(AuditLog.Action.FILE_DOWNLOAD, saved.getAction());
        assertEquals(AuditLog.ResourceType.FILE, saved.getResourceType());
        assertEquals(fileId, saved.getResourceId());
        assertEquals("unknown", saved.getIpAddress());
        assertTrue(saved.getDetails().contains("\"fileName\":\"data.csv\""));
    }

    @Test
    @DisplayName("logFileDownload: request extraction exception falls back to unknown IP")
    void logFileDownload_badRequestAttributes_savesUnknownIp() {
        RequestContextHolder.setRequestAttributes(mock(RequestAttributes.class));

        auditLogService.logFileDownload("user-2", UUID.randomUUID(), "data.csv");

        assertEquals("unknown", captureSavedAuditLog().getIpAddress());
    }

    @Test
    @DisplayName("logFileDownload: repository exception is swallowed")
    void logFileDownload_repositoryThrows_doesNotThrow() {
        when(auditLogRepository.save(any())).thenThrow(new RuntimeException("database down"));

        assertDoesNotThrow(() -> auditLogService.logFileDownload("user-2", UUID.randomUUID(), "data.csv"));
    }

    @Test
    @DisplayName("logFileDownload: details serialization failure saves null details")
    void logFileDownload_detailsSerializationThrows_savesNullDetails() throws Exception {
        ObjectMapper failingMapper = mock(ObjectMapper.class);
        when(failingMapper.writeValueAsString(any())).thenThrow(new RuntimeException("cannot serialize"));
        ReflectionTestUtils.setField(auditLogService, "objectMapper", failingMapper);

        auditLogService.logFileDownload("user-2", UUID.randomUUID(), "data.csv");

        assertNull(captureSavedAuditLog().getDetails());
    }


    // ── logFileDelete ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("logFileDelete: persists file deletion")
    void logFileDelete_savesAuditLog() {
        UUID fileId = UUID.randomUUID();
        setRequest(null, "192.0.2.55");

        auditLogService.logFileDelete("user-3", fileId, "old.txt");

        AuditLog saved = captureSavedAuditLog();
        assertEquals(AuditLog.Action.FILE_DELETE, saved.getAction());
        assertEquals(AuditLog.ResourceType.FILE, saved.getResourceType());
        assertEquals(fileId, saved.getResourceId());
        assertEquals("192.0.2.55", saved.getIpAddress());
        assertTrue(saved.getDetails().contains("\"fileName\":\"old.txt\""));
    }

    @Test
    @DisplayName("logFileDelete: repository exception is swallowed")
    void logFileDelete_repositoryThrows_doesNotThrow() {
        when(auditLogRepository.save(any())).thenThrow(new RuntimeException("database down"));

        assertDoesNotThrow(() -> auditLogService.logFileDelete("user-3", UUID.randomUUID(), "old.txt"));
    }

    // ── logFolderCreate ────────────────────────────────────────────────────────

    @Test
    @DisplayName("logFolderCreate: persists root folder creation")
    void logFolderCreate_rootFolder_savesAuditLog() {
        UUID folderId = UUID.randomUUID();

        auditLogService.logFolderCreate("user-4", folderId, "Root", null);

        AuditLog saved = captureSavedAuditLog();
        assertEquals(AuditLog.Action.FOLDER_CREATE, saved.getAction());
        assertEquals(AuditLog.ResourceType.FOLDER, saved.getResourceType());
        assertEquals(folderId, saved.getResourceId());
        assertTrue(saved.getDetails().contains("\"folderName\":\"Root\""));
        assertFalse(saved.getDetails().contains("parentFolderId"));
    }

    @Test
    @DisplayName("logFolderCreate: persists child folder creation with parent details")
    void logFolderCreate_childFolder_savesParentDetails() {
        UUID parentId = UUID.randomUUID();

        auditLogService.logFolderCreate("user-4", UUID.randomUUID(), "Child", parentId);

        assertTrue(captureSavedAuditLog().getDetails().contains(parentId.toString()));
    }

    @Test
    @DisplayName("logFolderCreate: repository exception is swallowed")
    void logFolderCreate_repositoryThrows_doesNotThrow() {
        when(auditLogRepository.save(any())).thenThrow(new RuntimeException("database down"));

        assertDoesNotThrow(() -> auditLogService.logFolderCreate("user-4", UUID.randomUUID(), "Root", null));
    }

    // ── logFolderDelete ────────────────────────────────────────────────────────

    @Test
    @DisplayName("logFolderDelete: persists folder deletion")
    void logFolderDelete_savesAuditLog() {
        UUID folderId = UUID.randomUUID();

        auditLogService.logFolderDelete("user-5", folderId, "Trash");

        AuditLog saved = captureSavedAuditLog();
        assertEquals(AuditLog.Action.FOLDER_DELETE, saved.getAction());
        assertEquals(AuditLog.ResourceType.FOLDER, saved.getResourceType());
        assertEquals(folderId, saved.getResourceId());
        assertTrue(saved.getDetails().contains("\"folderName\":\"Trash\""));
    }

    @Test
    @DisplayName("logFolderDelete: repository exception is swallowed")
    void logFolderDelete_repositoryThrows_doesNotThrow() {
        when(auditLogRepository.save(any())).thenThrow(new RuntimeException("database down"));

        assertDoesNotThrow(() -> auditLogService.logFolderDelete("user-5", UUID.randomUUID(), "Trash"));
    }

    // ── logShareGrant ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("logShareGrant: persists share grant for supplied resource type")
    void logShareGrant_savesAuditLog() {
        UUID resourceId = UUID.randomUUID();

        auditLogService.logShareGrant("grantor", resourceId, AuditLog.ResourceType.FOLDER, "grantee", "EDITOR");

        AuditLog saved = captureSavedAuditLog();
        assertEquals(AuditLog.Action.SHARE_GRANT, saved.getAction());
        assertEquals(AuditLog.ResourceType.FOLDER, saved.getResourceType());
        assertEquals(resourceId, saved.getResourceId());
        assertTrue(saved.getDetails().contains("\"grantedTo\":\"grantee\""));
        assertTrue(saved.getDetails().contains("\"role\":\"EDITOR\""));
    }

    @Test
    @DisplayName("logShareGrant: repository exception is swallowed")
    void logShareGrant_repositoryThrows_doesNotThrow() {
        when(auditLogRepository.save(any())).thenThrow(new RuntimeException("database down"));

        assertDoesNotThrow(() -> auditLogService.logShareGrant("grantor", UUID.randomUUID(), AuditLog.ResourceType.FILE, "grantee", "VIEWER"));
    }

    // ── logShareRevoke ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("logShareRevoke: persists share revoke for supplied resource type")
    void logShareRevoke_savesAuditLog() {
        UUID resourceId = UUID.randomUUID();

        auditLogService.logShareRevoke("owner", resourceId, AuditLog.ResourceType.FILE, "removed", "VIEWER");

        AuditLog saved = captureSavedAuditLog();
        assertEquals(AuditLog.Action.SHARE_REVOKE, saved.getAction());
        assertEquals(AuditLog.ResourceType.FILE, saved.getResourceType());
        assertEquals(resourceId, saved.getResourceId());
        assertTrue(saved.getDetails().contains("\"revokedFrom\":\"removed\""));
        assertTrue(saved.getDetails().contains("\"role\":\"VIEWER\""));
    }

    @Test
    @DisplayName("logShareRevoke: repository exception is swallowed")
    void logShareRevoke_repositoryThrows_doesNotThrow() {
        when(auditLogRepository.save(any())).thenThrow(new RuntimeException("database down"));

        assertDoesNotThrow(() -> auditLogService.logShareRevoke("owner", UUID.randomUUID(), AuditLog.ResourceType.FILE, "removed", "VIEWER"));
    }

    // ── getRecentLogs ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("getRecentLogs: returns repository page content and caps limit at 100")
    void getRecentLogs_success_capsLimitAt100() {
        AuditLog log = new AuditLog(AuditLog.Action.FILE_UPLOAD, "user", AuditLog.ResourceType.FILE, UUID.randomUUID(), null, "ip");
        when(auditLogRepository.findAll(any(Pageable.class))).thenReturn(new PageImpl<>(List.of(log)));

        List<AuditLog> result = auditLogService.getRecentLogs(500);

        assertEquals(List.of(log), result);
        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(auditLogRepository).findAll(pageableCaptor.capture());
        assertEquals(0, pageableCaptor.getValue().getPageNumber());
        assertEquals(100, pageableCaptor.getValue().getPageSize());
    }

    @Test
    @DisplayName("getRecentLogs: returns repository page content and uses requested limit")
    void getRecentLogs_success_usesRequestedLimit() {
        when(auditLogRepository.findAll(any(Pageable.class))).thenReturn(new PageImpl<>(List.of()));

        List<AuditLog> result = auditLogService.getRecentLogs(5);

        assertTrue(result.isEmpty());
        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(auditLogRepository).findAll(pageableCaptor.capture());
        assertEquals(5, pageableCaptor.getValue().getPageSize());
    }

    @Test
    @DisplayName("getRecentLogs: repository exception returns empty list")
    void getRecentLogs_repositoryThrows_returnsEmptyList() {
        when(auditLogRepository.findAll(any(Pageable.class))).thenThrow(new RuntimeException("database down"));

        List<AuditLog> result = auditLogService.getRecentLogs(25);

        assertTrue(result.isEmpty());
    }

    // ── getLogsForUser ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("getLogsForUser: returns repository page content and uses requested limit")
    void getLogsForUser_success_usesRequestedLimit() {
        AuditLog log = new AuditLog(AuditLog.Action.FILE_DOWNLOAD, "user", AuditLog.ResourceType.FILE, UUID.randomUUID(), null, "ip");
        when(auditLogRepository.findByUserId(eq("user"), any(Pageable.class))).thenReturn(new PageImpl<>(List.of(log)));

        List<AuditLog> result = auditLogService.getLogsForUser("user", 7);

        assertEquals(List.of(log), result);
        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(auditLogRepository).findByUserId(eq("user"), pageableCaptor.capture());
        assertEquals(7, pageableCaptor.getValue().getPageSize());
    }

    @Test
    @DisplayName("getLogsForUser: caps limit at 100")
    void getLogsForUser_success_capsLimitAt100() {
        when(auditLogRepository.findByUserId(eq("user"), any(Pageable.class))).thenReturn(new PageImpl<>(List.of()));

        List<AuditLog> result = auditLogService.getLogsForUser("user", 250);

        assertTrue(result.isEmpty());
        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(auditLogRepository).findByUserId(eq("user"), pageableCaptor.capture());
        assertEquals(100, pageableCaptor.getValue().getPageSize());
    }

    @Test
    @DisplayName("getLogsForUser: repository exception returns empty list")
    void getLogsForUser_repositoryThrows_returnsEmptyList() {
        when(auditLogRepository.findByUserId(eq("user"), any(Pageable.class))).thenThrow(new RuntimeException("database down"));

        List<AuditLog> result = auditLogService.getLogsForUser("user", 10);

        assertTrue(result.isEmpty());
    }

    // ── getLogsForResource ─────────────────────────────────────────────────────

    @Test
    @DisplayName("getLogsForResource: returns repository logs")
    void getLogsForResource_success_returnsLogs() {
        UUID resourceId = UUID.randomUUID();
        AuditLog log = new AuditLog(AuditLog.Action.FILE_DELETE, "user", AuditLog.ResourceType.FILE, resourceId, null, "ip");
        when(auditLogRepository.findByResourceId(resourceId)).thenReturn(List.of(log));

        List<AuditLog> result = auditLogService.getLogsForResource(resourceId);

        assertEquals(List.of(log), result);
    }

    @Test
    @DisplayName("getLogsForResource: repository exception returns empty list")
    void getLogsForResource_repositoryThrows_returnsEmptyList() {
        UUID resourceId = UUID.randomUUID();
        when(auditLogRepository.findByResourceId(resourceId)).thenThrow(new RuntimeException("database down"));

        List<AuditLog> result = auditLogService.getLogsForResource(resourceId);

        assertTrue(result.isEmpty());
    }

    private AuditLog captureSavedAuditLog() {
        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        return captor.getValue();
    }

    private void setRequestWithForwardedFor(String xForwardedFor, String remoteAddr) {
        setRequest(xForwardedFor, remoteAddr);
    }

    private void setRequest(String xForwardedFor, String remoteAddr) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(remoteAddr);
        if (xForwardedFor != null) {
            request.addHeader("X-Forwarded-For", xForwardedFor);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }
}
