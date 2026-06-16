package pt.isep.desofs.enderchest.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.multipart.MultipartFile;
import pt.isep.desofs.enderchest.exception.resource.FileNotFoundException;
import pt.isep.desofs.enderchest.exception.security.FileAccessDeniedException;
import pt.isep.desofs.enderchest.exception.security.FileUploadException;
import pt.isep.desofs.enderchest.service.FileService;
import pt.isep.desofs.enderchest.service.FileStorageService;
import pt.isep.desofs.enderchest.service.dto.FileDeleteResponse;
import pt.isep.desofs.enderchest.service.dto.UploadResponse;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("FileController Unit Tests")
class FileControllerTest {

    private static final String USER_ID = "auth0|user-123";
    private static final String EMAIL = "user@example.com";
    private static final String HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    @Mock
    private FileStorageService fileStorageService;

    @Mock
    private FileService fileService;

    @Mock
    private MultipartFile multipartFile;

    @InjectMocks
    private FileController controller;

    @Test
    @DisplayName("uploadFile: stores file and returns 201")
    void uploadFile_success_returnsCreated() {
        UUID fileId = UUID.randomUUID();
        UploadResponse uploadResponse = new UploadResponse(fileId, HASH, 42L, LocalDateTime.now(), "text/plain");
        when(fileStorageService.uploadFile(multipartFile, USER_ID, null)).thenReturn(uploadResponse);

        ResponseEntity<UploadResponse> response = controller.uploadFile(multipartFile, null, jwt());

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertSame(uploadResponse, response.getBody());
        verify(fileStorageService).uploadFile(multipartFile, USER_ID, null);
    }

    @Test
    @DisplayName("uploadFile: passes folder id to storage service")
    void uploadFile_withFolder_passesFolderId() {
        UUID folderId = UUID.randomUUID();
        UploadResponse uploadResponse = new UploadResponse(UUID.randomUUID(), HASH, 99L, LocalDateTime.now(), "application/pdf");
        when(fileStorageService.uploadFile(multipartFile, USER_ID, folderId)).thenReturn(uploadResponse);

        ResponseEntity<UploadResponse> response = controller.uploadFile(multipartFile, folderId, jwt());

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals("application/pdf", response.getBody().getMimeType());
        verify(fileStorageService).uploadFile(multipartFile, USER_ID, folderId);
    }

    @Test
    @DisplayName("uploadFile: storage service exception is rethrown")
    void uploadFile_serviceException_rethrows() {
        when(fileStorageService.uploadFile(multipartFile, USER_ID, null)).thenThrow(new FileUploadException("failed"));

        assertThrows(FileUploadException.class, () -> controller.uploadFile(multipartFile, null, jwt()));
    }

    @Test
    @DisplayName("downloadFile: existing stored file returns 200 with headers")
    void downloadFile_existingResource_returnsOk() {
        UUID fileId = UUID.randomUUID();
        pt.isep.desofs.enderchest.entity.File file = file(fileId,
                "report.txt",
                "src/test/java/pt/isep/desofs/enderchest/controller/FileControllerTest.java");
        when(fileService.downloadFile(fileId, USER_ID, EMAIL)).thenReturn(file);

        ResponseEntity<Resource> response = controller.downloadFile(fileId, jwt());

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().exists());
        assertEquals(MediaType.TEXT_PLAIN, response.getHeaders().getContentType());
        assertEquals(123L, response.getHeaders().getContentLength());
        assertTrue(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION).contains("report.txt"));
    }

    @Test
    @DisplayName("downloadFile: missing storage resource returns 404")
    void downloadFile_missingResource_returnsNotFound() {
        UUID fileId = UUID.randomUUID();
        pt.isep.desofs.enderchest.entity.File file = file(fileId,
                "missing.txt",
                "src/test/java/pt/isep/desofs/enderchest/controller/missing-file-does-not-exist.txt");
        when(fileService.downloadFile(fileId, USER_ID, EMAIL)).thenReturn(file);

        ResponseEntity<Resource> response = controller.downloadFile(fileId, jwt());

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("downloadFile: file service not found returns 404")
    void downloadFile_fileNotFound_returnsNotFound() {
        UUID fileId = UUID.randomUUID();
        when(fileService.downloadFile(fileId, USER_ID, EMAIL)).thenThrow(new FileNotFoundException(fileId));

        ResponseEntity<Resource> response = controller.downloadFile(fileId, jwt());

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("downloadFile: access denied returns 403")
    void downloadFile_accessDenied_returnsForbidden() {
        UUID fileId = UUID.randomUUID();
        when(fileService.downloadFile(fileId, USER_ID, EMAIL)).thenThrow(new FileAccessDeniedException(fileId, null));

        ResponseEntity<Resource> response = controller.downloadFile(fileId, jwt());

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("deleteFile: successful delete returns 200")
    void deleteFile_success_returnsOk() {
        UUID fileId = UUID.randomUUID();

        ResponseEntity<FileDeleteResponse> response = controller.deleteFile(fileId, jwt());

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(fileId, response.getBody().getFileId());
        assertNotNull(response.getBody().getDeletedAt());
        assertEquals("File deleted successfully", response.getBody().getMessage());
        verify(fileService).deleteFile(fileId, USER_ID, EMAIL);
    }

    @Test
    @DisplayName("deleteFile: file not found returns 404")
    void deleteFile_fileNotFound_returnsNotFound() {
        UUID fileId = UUID.randomUUID();
        doThrow(new FileNotFoundException(fileId)).when(fileService).deleteFile(fileId, USER_ID, EMAIL);

        ResponseEntity<FileDeleteResponse> response = controller.deleteFile(fileId, jwt());

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("deleteFile: access denied returns 403")
    void deleteFile_accessDenied_returnsForbidden() {
        UUID fileId = UUID.randomUUID();
        doThrow(new FileAccessDeniedException(fileId, null)).when(fileService).deleteFile(fileId, USER_ID, EMAIL);

        ResponseEntity<FileDeleteResponse> response = controller.deleteFile(fileId, jwt());

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("adminHealth: returns OK message")
    void adminHealth_returnsOk() {
        ResponseEntity<String> response = controller.adminHealth();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Admin health check: OK", response.getBody());
    }

    private static Jwt jwt() {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .subject(USER_ID)
                .claim("email", EMAIL)
                .build();
    }

    private static pt.isep.desofs.enderchest.entity.File file(UUID fileId, String originalName, String storageLocation) {
        pt.isep.desofs.enderchest.entity.File file = new pt.isep.desofs.enderchest.entity.File(
                originalName,
                UUID.randomUUID().toString(),
                HASH,
                123L,
                "text/plain",
                USER_ID,
                storageLocation
        );
        file.setId(fileId);
        return file;
    }
}
