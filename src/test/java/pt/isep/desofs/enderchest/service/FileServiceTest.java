package pt.isep.desofs.enderchest.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pt.isep.desofs.enderchest.entity.AccessShare;
import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.entity.User;
import pt.isep.desofs.enderchest.exception.resource.FileNotFoundException;
import pt.isep.desofs.enderchest.exception.security.FileAccessDeniedException;
import pt.isep.desofs.enderchest.repository.AccessShareRepository;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.repository.UserRepository;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("FileService Unit Tests")
class FileServiceTest {

    @Mock
    private FileRepository fileRepository;

    @Mock
    private AccessShareRepository accessShareRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private FileService fileService;

    // ── downloadFile ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("downloadFile: owner can download active file")
    void downloadFile_owner_returnsFile() throws FileNotFoundException, FileAccessDeniedException {
        UUID fileId = UUID.randomUUID();
        File file = activeFile(fileId, "auth0|owner");
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));

        File result = fileService.downloadFile(fileId, "auth0|owner", "owner@example.com");

        assertSame(file, result);
        verifyNoInteractions(userRepository, accessShareRepository);
    }

    @Test
    @DisplayName("downloadFile: shared viewer can download active file")
    void downloadFile_sharedViewer_returnsFile() throws FileNotFoundException, FileAccessDeniedException {
        UUID fileId = UUID.randomUUID();
        UUID callerUuid = UUID.randomUUID();
        File file = activeFile(fileId, "auth0|owner");
        User caller = user(callerUuid, "viewer@example.com");
        AccessShare share = new AccessShare(fileId, AccessShare.ResourceType.FILE, callerUuid, AccessShare.RoleType.VIEWER);
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));
        when(userRepository.findByEmail("viewer@example.com")).thenReturn(Optional.of(caller));
        when(accessShareRepository.findByResourceIdAndResourceTypeAndGrantedToUserId(fileId, AccessShare.ResourceType.FILE, callerUuid))
                .thenReturn(Optional.of(share));

        File result = fileService.downloadFile(fileId, "auth0|viewer", "viewer@example.com");

        assertSame(file, result);
    }

    @Test
    @DisplayName("downloadFile: missing file throws FileNotFoundException")
    void downloadFile_missing_throwsFileNotFoundException() {
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.empty());

        assertThrows(FileNotFoundException.class,
                () -> fileService.downloadFile(fileId, "auth0|user", "user@example.com"));
        verifyNoInteractions(userRepository, accessShareRepository);
    }

    @Test
    @DisplayName("downloadFile: deleted file throws FileNotFoundException")
    void downloadFile_deleted_throwsFileNotFoundException() {
        UUID fileId = UUID.randomUUID();
        File file = deletedFile(fileId, "auth0|owner");
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));

        assertThrows(FileNotFoundException.class,
                () -> fileService.downloadFile(fileId, "auth0|owner", "owner@example.com"));
        verifyNoInteractions(userRepository, accessShareRepository);
    }

    @Test
    @DisplayName("downloadFile: non-owner with null email is denied")
    void downloadFile_nonOwnerNullEmail_throwsAccessDenied() {
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(activeFile(fileId, "auth0|owner")));

        assertThrows(FileAccessDeniedException.class,
                () -> fileService.downloadFile(fileId, "auth0|other", null));
        verifyNoInteractions(userRepository, accessShareRepository);
    }

    @Test
    @DisplayName("downloadFile: non-owner with blank email is denied")
    void downloadFile_nonOwnerBlankEmail_throwsAccessDenied() {
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(activeFile(fileId, "auth0|owner")));

        assertThrows(FileAccessDeniedException.class,
                () -> fileService.downloadFile(fileId, "auth0|other", "  "));
        verifyNoInteractions(userRepository, accessShareRepository);
    }

    @Test
    @DisplayName("downloadFile: unresolved email is denied")
    void downloadFile_unresolvedEmail_throwsAccessDenied() {
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(activeFile(fileId, "auth0|owner")));
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        assertThrows(FileAccessDeniedException.class,
                () -> fileService.downloadFile(fileId, "auth0|missing", "missing@example.com"));
        verifyNoInteractions(accessShareRepository);
    }

    @Test
    @DisplayName("downloadFile: resolved user without share is denied")
    void downloadFile_noShare_throwsAccessDenied() {
        UUID fileId = UUID.randomUUID();
        UUID callerUuid = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(activeFile(fileId, "auth0|owner")));
        when(userRepository.findByEmail("other@example.com")).thenReturn(Optional.of(user(callerUuid, "other@example.com")));
        when(accessShareRepository.findByResourceIdAndResourceTypeAndGrantedToUserId(fileId, AccessShare.ResourceType.FILE, callerUuid))
                .thenReturn(Optional.empty());

        assertThrows(FileAccessDeniedException.class,
                () -> fileService.downloadFile(fileId, "auth0|other", "other@example.com"));
    }

    // ── deleteFile ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("deleteFile: owner soft deletes active file and saves it")
    void deleteFile_owner_softDeletesAndSaves() throws FileNotFoundException, FileAccessDeniedException {
        UUID fileId = UUID.randomUUID();
        File file = activeFile(fileId, "auth0|owner");
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));
        when(fileRepository.save(file)).thenReturn(file);

        fileService.deleteFile(fileId, "auth0|owner", "owner@example.com");

        assertTrue(file.getIsDeleted());
        assertNotNull(file.getDeletedAt());
        verify(fileRepository).save(file);
        verifyNoInteractions(userRepository, accessShareRepository);
    }

    @Test
    @DisplayName("deleteFile: shared owner can soft delete active file")
    void deleteFile_sharedOwner_softDeletesAndSaves() throws FileNotFoundException, FileAccessDeniedException {
        UUID fileId = UUID.randomUUID();
        UUID callerUuid = UUID.randomUUID();
        File file = activeFile(fileId, "auth0|owner");
        User caller = user(callerUuid, "coowner@example.com");
        AccessShare share = new AccessShare(fileId, AccessShare.ResourceType.FILE, callerUuid, AccessShare.RoleType.OWNER);
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));
        when(userRepository.findByEmail("coowner@example.com")).thenReturn(Optional.of(caller));
        when(accessShareRepository.findByResourceIdAndResourceTypeAndGrantedToUserId(fileId, AccessShare.ResourceType.FILE, callerUuid))
                .thenReturn(Optional.of(share));
        when(fileRepository.save(file)).thenReturn(file);

        fileService.deleteFile(fileId, "auth0|coowner", "coowner@example.com");

        assertTrue(file.getIsDeleted());
        verify(fileRepository).save(file);
    }

    @Test
    @DisplayName("deleteFile: missing file throws FileNotFoundException")
    void deleteFile_missing_throwsFileNotFoundException() {
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.empty());

        assertThrows(FileNotFoundException.class,
                () -> fileService.deleteFile(fileId, "auth0|owner", "owner@example.com"));
        verify(fileRepository, never()).save(any());
        verifyNoInteractions(userRepository, accessShareRepository);
    }

    @Test
    @DisplayName("deleteFile: already deleted file throws FileNotFoundException")
    void deleteFile_deleted_throwsFileNotFoundException() {
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(deletedFile(fileId, "auth0|owner")));

        assertThrows(FileNotFoundException.class,
                () -> fileService.deleteFile(fileId, "auth0|owner", "owner@example.com"));
        verify(fileRepository, never()).save(any());
        verifyNoInteractions(userRepository, accessShareRepository);
    }

    @Test
    @DisplayName("deleteFile: shared editor is denied owner-level operation")
    void deleteFile_sharedEditor_throwsAccessDenied() {
        UUID fileId = UUID.randomUUID();
        UUID callerUuid = UUID.randomUUID();
        File file = activeFile(fileId, "auth0|owner");
        AccessShare share = new AccessShare(fileId, AccessShare.ResourceType.FILE, callerUuid, AccessShare.RoleType.EDITOR);
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));
        when(userRepository.findByEmail("editor@example.com")).thenReturn(Optional.of(user(callerUuid, "editor@example.com")));
        when(accessShareRepository.findByResourceIdAndResourceTypeAndGrantedToUserId(fileId, AccessShare.ResourceType.FILE, callerUuid))
                .thenReturn(Optional.of(share));

        assertThrows(FileAccessDeniedException.class,
                () -> fileService.deleteFile(fileId, "auth0|editor", "editor@example.com"));
        assertFalse(file.getIsDeleted());
        verify(fileRepository, never()).save(any());
    }

    @Test
    @DisplayName("deleteFile: resolved user without share is denied")
    void deleteFile_noShare_throwsAccessDenied() {
        UUID fileId = UUID.randomUUID();
        UUID callerUuid = UUID.randomUUID();
        File file = activeFile(fileId, "auth0|owner");
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));
        when(userRepository.findByEmail("other@example.com")).thenReturn(Optional.of(user(callerUuid, "other@example.com")));
        when(accessShareRepository.findByResourceIdAndResourceTypeAndGrantedToUserId(fileId, AccessShare.ResourceType.FILE, callerUuid))
                .thenReturn(Optional.empty());

        assertThrows(FileAccessDeniedException.class,
                () -> fileService.deleteFile(fileId, "auth0|other", "other@example.com"));
        verify(fileRepository, never()).save(any());
    }

    @Test
    @DisplayName("deleteFile: non-owner with blank email is denied")
    void deleteFile_blankEmail_throwsAccessDenied() {
        UUID fileId = UUID.randomUUID();
        File file = activeFile(fileId, "auth0|owner");
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));

        assertThrows(FileAccessDeniedException.class,
                () -> fileService.deleteFile(fileId, "auth0|other", ""));
        verify(fileRepository, never()).save(any());
        verifyNoInteractions(userRepository, accessShareRepository);
    }

    @Test
    @DisplayName("deleteFile: unresolved email is denied")
    void deleteFile_unresolvedEmail_throwsAccessDenied() {
        UUID fileId = UUID.randomUUID();
        File file = activeFile(fileId, "auth0|owner");
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        assertThrows(FileAccessDeniedException.class,
                () -> fileService.deleteFile(fileId, "auth0|missing", "missing@example.com"));
        verify(fileRepository, never()).save(any());
        verifyNoInteractions(accessShareRepository);
    }

    private File activeFile(UUID fileId, String uploadedBy) {
        File file = new File("document.txt", fileId + ".txt", "a".repeat(64), 42L, "text/plain", uploadedBy, "storage/path");
        file.setId(fileId);
        file.setIsDeleted(Boolean.FALSE);
        return file;
    }

    private File deletedFile(UUID fileId, String uploadedBy) {
        File file = activeFile(fileId, uploadedBy);
        file.softDelete();
        return file;
    }

    private User user(UUID userId, String email) {
        User user = new User("username-" + userId, email, "hash", "First", "Last");
        user.setUserId(userId);
        return user;
    }
}
