package pt.isep.desofs.enderchest.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.entity.FileVersion;
import pt.isep.desofs.enderchest.exception.resource.FileNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.FileVersionNotFoundException;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.repository.FileVersionRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("FileVersionService Unit Tests")
class FileVersionServiceTest {

    @Mock
    private FileVersionRepository fileVersionRepository;

    @Mock
    private FileRepository fileRepository;

    @InjectMocks
    private FileVersionService fileVersionService;

    // ── listFileVersionsByFileId ───────────────────────────────────────────────

    @Test
    @DisplayName("listFileVersionsByFileId: active file returns versions in repository order")
    void listFileVersionsByFileId_activeFile_returnsVersions() throws FileNotFoundException {
        UUID fileId = UUID.randomUUID();
        File file = activeFile(fileId);
        FileVersion v1 = version(file, UUID.randomUUID(), 1);
        FileVersion v2 = version(file, UUID.randomUUID(), 2);
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));
        when(fileVersionRepository.findByFileIdOrderByVersionNumberAsc(fileId)).thenReturn(List.of(v1, v2));

        List<FileVersion> result = fileVersionService.listFileVersionsByFileId(fileId);

        assertEquals(List.of(v1, v2), result);
    }

    @Test
    @DisplayName("listFileVersionsByFileId: active file with no versions returns empty list")
    void listFileVersionsByFileId_noVersions_returnsEmptyList() throws FileNotFoundException {
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(activeFile(fileId)));
        when(fileVersionRepository.findByFileIdOrderByVersionNumberAsc(fileId)).thenReturn(List.of());

        List<FileVersion> result = fileVersionService.listFileVersionsByFileId(fileId);

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("listFileVersionsByFileId: missing file throws FileNotFoundException")
    void listFileVersionsByFileId_missingFile_throwsFileNotFoundException() {
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.empty());

        assertThrows(FileNotFoundException.class,
                () -> fileVersionService.listFileVersionsByFileId(fileId));
        verifyNoInteractions(fileVersionRepository);
    }

    @Test
    @DisplayName("listFileVersionsByFileId: deleted file throws FileNotFoundException")
    void listFileVersionsByFileId_deletedFile_throwsFileNotFoundException() {
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(deletedFile(fileId)));

        assertThrows(FileNotFoundException.class,
                () -> fileVersionService.listFileVersionsByFileId(fileId));
        verifyNoInteractions(fileVersionRepository);
    }

    // ── getFileVersionById ─────────────────────────────────────────────────────

    @Test
    @DisplayName("getFileVersionById: existing version belonging to active file is returned")
    void getFileVersionById_existingMatchingVersion_returnsVersion()
            throws FileNotFoundException, FileVersionNotFoundException {
        UUID fileId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        File file = activeFile(fileId);
        FileVersion version = version(file, versionId, 3);
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));
        when(fileVersionRepository.findById(versionId)).thenReturn(Optional.of(version));

        FileVersion result = fileVersionService.getFileVersionById(fileId, versionId);

        assertSame(version, result);
        assertEquals(3, result.getVersionNumber());
    }

    @Test
    @DisplayName("getFileVersionById: missing file throws FileNotFoundException")
    void getFileVersionById_missingFile_throwsFileNotFoundException() {
        UUID fileId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.empty());

        assertThrows(FileNotFoundException.class,
                () -> fileVersionService.getFileVersionById(fileId, versionId));
        verifyNoInteractions(fileVersionRepository);
    }

    @Test
    @DisplayName("getFileVersionById: deleted file throws FileNotFoundException")
    void getFileVersionById_deletedFile_throwsFileNotFoundException() {
        UUID fileId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(deletedFile(fileId)));

        assertThrows(FileNotFoundException.class,
                () -> fileVersionService.getFileVersionById(fileId, versionId));
        verifyNoInteractions(fileVersionRepository);
    }

    @Test
    @DisplayName("getFileVersionById: missing version throws FileVersionNotFoundException")
    void getFileVersionById_missingVersion_throwsFileVersionNotFoundException() {
        UUID fileId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(activeFile(fileId)));
        when(fileVersionRepository.findById(versionId)).thenReturn(Optional.empty());

        assertThrows(FileVersionNotFoundException.class,
                () -> fileVersionService.getFileVersionById(fileId, versionId));
    }

    @Test
    @DisplayName("getFileVersionById: version for another file throws FileVersionNotFoundException")
    void getFileVersionById_versionBelongsToDifferentFile_throwsFileVersionNotFoundException() {
        UUID requestedFileId = UUID.randomUUID();
        UUID otherFileId = UUID.randomUUID();
        UUID versionId = UUID.randomUUID();
        when(fileRepository.findById(requestedFileId)).thenReturn(Optional.of(activeFile(requestedFileId)));
        when(fileVersionRepository.findById(versionId)).thenReturn(Optional.of(version(activeFile(otherFileId), versionId, 1)));

        assertThrows(FileVersionNotFoundException.class,
                () -> fileVersionService.getFileVersionById(requestedFileId, versionId));
    }

    // ── createFileVersion ──────────────────────────────────────────────────────

    @Test
    @DisplayName("createFileVersion: active file creates and saves populated version")
    void createFileVersion_activeFile_savesPopulatedVersion() throws FileNotFoundException {
        UUID fileId = UUID.randomUUID();
        UUID savedVersionId = UUID.randomUUID();
        File file = activeFile(fileId);
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(file));
        when(fileVersionRepository.save(any(FileVersion.class))).thenAnswer(invocation -> {
            FileVersion saved = invocation.getArgument(0);
            saved.setId(savedVersionId);
            return saved;
        });

        FileVersion result = fileVersionService.createFileVersion(fileId, 4, "b".repeat(64), "auth0|editor", "Replaced content");

        assertEquals(savedVersionId, result.getId());
        ArgumentCaptor<FileVersion> captor = ArgumentCaptor.forClass(FileVersion.class);
        verify(fileVersionRepository).save(captor.capture());
        FileVersion saved = captor.getValue();
        assertSame(file, saved.getFile());
        assertEquals(4, saved.getVersionNumber());
        assertEquals("b".repeat(64), saved.getSha256Hash());
        assertEquals("auth0|editor", saved.getModifiedBy());
        assertEquals("Replaced content", saved.getChangeDescription());
        assertNotNull(saved.getModifiedAt());
    }

    @Test
    @DisplayName("createFileVersion: missing file throws FileNotFoundException")
    void createFileVersion_missingFile_throwsFileNotFoundException() {
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.empty());

        assertThrows(FileNotFoundException.class,
                () -> fileVersionService.createFileVersion(fileId, 1, "c".repeat(64), "auth0|user", "Initial upload"));
        verify(fileVersionRepository, never()).save(any());
    }

    @Test
    @DisplayName("createFileVersion: deleted file throws FileNotFoundException")
    void createFileVersion_deletedFile_throwsFileNotFoundException() {
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findById(fileId)).thenReturn(Optional.of(deletedFile(fileId)));

        assertThrows(FileNotFoundException.class,
                () -> fileVersionService.createFileVersion(fileId, 1, "d".repeat(64), "auth0|user", "Initial upload"));
        verify(fileVersionRepository, never()).save(any());
    }

    private File activeFile(UUID fileId) {
        File file = new File("document.txt", fileId + ".txt", "a".repeat(64), 100L, "text/plain", "auth0|owner", "storage/path");
        file.setId(fileId);
        file.setIsDeleted(Boolean.FALSE);
        return file;
    }

    private File deletedFile(UUID fileId) {
        File file = activeFile(fileId);
        file.softDelete();
        return file;
    }

    private FileVersion version(File file, UUID versionId, int versionNumber) {
        FileVersion version = new FileVersion(file, versionNumber, "a".repeat(64), "auth0|user", "Change " + versionNumber);
        version.setId(versionId);
        return version;
    }
}
