package pt.isep.desofs.enderchest.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pt.isep.desofs.enderchest.entity.Folder;
import pt.isep.desofs.enderchest.exception.resource.CircularReferenceFolderException;
import pt.isep.desofs.enderchest.exception.resource.FolderNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.InvalidFolderNameException;
import pt.isep.desofs.enderchest.repository.FolderRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("FolderService Unit Tests")
class FolderServiceTest {

    @Mock
    private FolderRepository folderRepository;

    @InjectMocks
    private FolderService folderService;

    // ── createFolder ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("createFolder: valid root folder is saved and returned")
    void createFolder_validRootFolder_savesCalled() {
        UUID ownerId = UUID.randomUUID();
        Folder saved = new Folder("Docs", ownerId, null);
        when(folderRepository.save(any(Folder.class))).thenReturn(saved);

        Folder result = folderService.createFolder("Docs", ownerId, null);

        assertNotNull(result);
        verify(folderRepository).save(any(Folder.class));
    }

    @Test
    @DisplayName("createFolder: null name throws IllegalArgumentException")
    void createFolder_nullName_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class,
                () -> folderService.createFolder(null, UUID.randomUUID(), null));
        verify(folderRepository, never()).save(any());
    }

    @Test
    @DisplayName("createFolder: blank name throws IllegalArgumentException")
    void createFolder_blankName_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class,
                () -> folderService.createFolder("   ", UUID.randomUUID(), null));
        verify(folderRepository, never()).save(any());
    }

    @Test
    @DisplayName("createFolder: null ownerId throws IllegalArgumentException")
    void createFolder_nullOwner_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class,
                () -> folderService.createFolder("Docs", null, null));
        verify(folderRepository, never()).save(any());
    }

    @Test
    @DisplayName("createFolder: non-existent parentId throws IllegalArgumentException")
    void createFolder_missingParent_throwsIllegalArgument() {
        UUID parentId = UUID.randomUUID();
        when(folderRepository.findByFolderIdAndIsDeletedFalse(parentId)).thenReturn(Optional.empty());

        assertThrows(IllegalArgumentException.class,
                () -> folderService.createFolder("Sub", UUID.randomUUID(), parentId));
        verify(folderRepository, never()).save(any());
    }

    // ── getFolderById / getFolderByIdOrThrow ───────────────────────────────────

    @Test
    @DisplayName("getFolderById: returns empty Optional for missing folder")
    void getFolderById_missing_returnsEmpty() {
        UUID id = UUID.randomUUID();
        when(folderRepository.findByFolderIdAndIsDeletedFalse(id)).thenReturn(Optional.empty());

        assertTrue(folderService.getFolderById(id).isEmpty());
    }

    @Test
    @DisplayName("getFolderByIdOrThrow: missing folder throws FolderNotFoundException")
    void getFolderByIdOrThrow_missing_throws() {
        UUID id = UUID.randomUUID();
        when(folderRepository.findByFolderIdAndIsDeletedFalse(id)).thenReturn(Optional.empty());

        assertThrows(FolderNotFoundException.class, () -> folderService.getFolderByIdOrThrow(id));
    }

    // ── softDeleteFolder ──────────────────────────────────────────────────────

    @Test
    @DisplayName("softDeleteFolder: existing folder has softDelete() called and is saved")
    void softDeleteFolder_existing_softDeleteCalledAndSaved() {
        UUID id = UUID.randomUUID();
        Folder folder = mock(Folder.class);
        when(folderRepository.findByFolderIdAndIsDeletedFalse(id)).thenReturn(Optional.of(folder));
        when(folderRepository.save(folder)).thenReturn(folder);

        folderService.softDeleteFolder(id);

        verify(folder).softDelete();
        verify(folderRepository).save(folder);
    }

    // ── renameFolder ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("renameFolder: blank new name throws InvalidFolderNameException")
    void renameFolder_blankName_throws() {
        assertThrows(InvalidFolderNameException.class,
                () -> folderService.renameFolder(UUID.randomUUID(), "   "));
    }

    // ── moveFolder ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("moveFolder: moving folder to itself throws CircularReferenceFolderException")
    void moveFolder_toSelf_throwsCircular() {
        UUID id = UUID.randomUUID();
        Folder folder = new Folder("F", UUID.randomUUID(), null);
        when(folderRepository.findByFolderIdAndIsDeletedFalse(id)).thenReturn(Optional.of(folder));

        assertThrows(CircularReferenceFolderException.class,
                () -> folderService.moveFolder(id, id));
    }

    // ── folderExists ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("folderExists: returns false for missing folder")
    void folderExists_missing_returnsFalse() {
        UUID id = UUID.randomUUID();
        when(folderRepository.findByFolderIdAndIsDeletedFalse(id)).thenReturn(Optional.empty());

        assertFalse(folderService.folderExists(id));
    }

    @Test
    @DisplayName("folderExists: returns true for existing active folder")
    void folderExists_existing_returnsTrue() {
        UUID id = UUID.randomUUID();
        Folder folder = new Folder("F", UUID.randomUUID(), null);
        when(folderRepository.findByFolderIdAndIsDeletedFalse(id)).thenReturn(Optional.of(folder));

        assertTrue(folderService.folderExists(id));
    }

    // ── listAllUserFolders ────────────────────────────────────────────────────

    @Test
    @DisplayName("listAllUserFolders: returns list from repository")
    void listAllUserFolders_returnsRepositoryResult() {
        UUID ownerId = UUID.randomUUID();
        List<Folder> folders = List.of(new Folder("A", ownerId, null), new Folder("B", ownerId, null));
        when(folderRepository.findByOwnerIdAndIsDeletedFalse(ownerId)).thenReturn(folders);

        List<Folder> result = folderService.listAllUserFolders(ownerId);

        assertEquals(2, result.size());
    }
}
