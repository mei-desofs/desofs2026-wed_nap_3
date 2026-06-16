package pt.isep.desofs.enderchest.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.entity.FileVersion;
import pt.isep.desofs.enderchest.exception.resource.FileNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.FileVersionNotFoundException;
import pt.isep.desofs.enderchest.service.FileVersionService;
import pt.isep.desofs.enderchest.service.dto.FileVersionResponse;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("FileVersionController Unit Tests")
class FileVersionControllerTest {

    private static final String USER_ID = "123e4567-e89b-12d3-a456-426614174000";
    private static final String HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    @Mock
    private FileVersionService fileVersionService;

    @InjectMocks
    private FileVersionController controller;

    @Test
    @DisplayName("listFileVersions: non-empty history returns 200")
    void listFileVersions_nonEmpty_returnsOk() {
        UUID fileId = UUID.randomUUID();
        FileVersion version = version(fileId, UUID.randomUUID(), 1, "Initial upload");
        when(fileVersionService.listFileVersionsByFileId(fileId)).thenReturn(List.of(version));

        ResponseEntity<List<FileVersionResponse>> response = controller.listFileVersions(fileId, USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, response.getBody().size());
        assertEquals(1, response.getBody().getFirst().getVersionNumber());
        assertEquals(HASH, response.getBody().getFirst().getSha256Hash());
    }

    @Test
    @DisplayName("listFileVersions: empty history returns 200")
    void listFileVersions_empty_returnsOk() {
        UUID fileId = UUID.randomUUID();
        when(fileVersionService.listFileVersionsByFileId(fileId)).thenReturn(List.of());

        ResponseEntity<List<FileVersionResponse>> response = controller.listFileVersions(fileId, USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().isEmpty());
    }

    @Test
    @DisplayName("listFileVersions: missing file returns 404")
    void listFileVersions_missingFile_returnsNotFound() {
        UUID fileId = UUID.randomUUID();
        when(fileVersionService.listFileVersionsByFileId(fileId)).thenThrow(new FileNotFoundException(fileId));

        ResponseEntity<List<FileVersionResponse>> response = controller.listFileVersions(fileId, USER_ID);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("listFileVersions: deleted file returns 410")
    void listFileVersions_deletedFile_returnsGone() {
        UUID fileId = UUID.randomUUID();
        when(fileVersionService.listFileVersionsByFileId(fileId))
                .thenThrow(new FileNotFoundException("File has been deleted: " + fileId));

        ResponseEntity<List<FileVersionResponse>> response = controller.listFileVersions(fileId, USER_ID);

        assertEquals(HttpStatus.GONE, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("listFileVersions: null exception message returns 404")
    void listFileVersions_nullExceptionMessage_returnsNotFound() {
        UUID fileId = UUID.randomUUID();
        when(fileVersionService.listFileVersionsByFileId(fileId)).thenThrow(new FileNotFoundException((String) null));

        ResponseEntity<List<FileVersionResponse>> response = controller.listFileVersions(fileId, USER_ID);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    @DisplayName("getFileVersion: existing version returns 200")
    void getFileVersion_success_returnsOk() {
        UUID fileId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        FileVersion version = version(fileId, versionId, 2, "Updated content");
        when(fileVersionService.getFileVersionById(fileId, versionId)).thenReturn(version);

        ResponseEntity<FileVersionResponse> response = controller.getFileVersion(fileId, versionId, USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(versionId, response.getBody().getVersionId());
        assertEquals(2, response.getBody().getVersionNumber());
        assertEquals("Updated content", response.getBody().getChangeDescription());
        assertEquals(USER_ID, response.getBody().getModifiedBy());
    }

    @Test
    @DisplayName("getFileVersion: missing file returns 404")
    void getFileVersion_missingFile_returnsNotFound() {
        UUID fileId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        when(fileVersionService.getFileVersionById(fileId, versionId)).thenThrow(new FileNotFoundException(fileId));

        ResponseEntity<FileVersionResponse> response = controller.getFileVersion(fileId, versionId, USER_ID);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("getFileVersion: deleted file returns 410")
    void getFileVersion_deletedFile_returnsGone() {
        UUID fileId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        when(fileVersionService.getFileVersionById(fileId, versionId))
                .thenThrow(new FileNotFoundException("File has been deleted: " + fileId));

        ResponseEntity<FileVersionResponse> response = controller.getFileVersion(fileId, versionId, USER_ID);

        assertEquals(HttpStatus.GONE, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("getFileVersion: null file exception message returns 404")
    void getFileVersion_nullExceptionMessage_returnsNotFound() {
        UUID fileId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        when(fileVersionService.getFileVersionById(fileId, versionId)).thenThrow(new FileNotFoundException((String) null));

        ResponseEntity<FileVersionResponse> response = controller.getFileVersion(fileId, versionId, USER_ID);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    @DisplayName("getFileVersion: missing version returns 404")
    void getFileVersion_missingVersion_returnsNotFound() {
        UUID fileId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        when(fileVersionService.getFileVersionById(fileId, versionId)).thenThrow(new FileVersionNotFoundException(versionId));

        ResponseEntity<FileVersionResponse> response = controller.getFileVersion(fileId, versionId, USER_ID);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
    }

    private static FileVersion version(UUID fileId, UUID versionId, int versionNumber, String changeDescription) {
        File file = new File("file.txt", UUID.randomUUID().toString(), HASH, 10L, "text/plain", USER_ID, "storage");
        file.setId(fileId);
        FileVersion version = new FileVersion(file, versionNumber, HASH, USER_ID, changeDescription);
        version.setId(versionId);
        version.setModifiedAt(LocalDateTime.now());
        version.setCreatedAt(LocalDateTime.now());
        return version;
    }
}
