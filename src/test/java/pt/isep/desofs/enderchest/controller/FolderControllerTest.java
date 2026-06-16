package pt.isep.desofs.enderchest.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import pt.isep.desofs.enderchest.entity.Folder;
import pt.isep.desofs.enderchest.exception.resource.FolderNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.InvalidFolderNameException;
import pt.isep.desofs.enderchest.service.FolderService;
import pt.isep.desofs.enderchest.service.dto.FolderDeleteResponse;
import pt.isep.desofs.enderchest.service.dto.FolderRequest;
import pt.isep.desofs.enderchest.service.dto.FolderResponse;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("FolderController Unit Tests")
class FolderControllerTest {

    private static final String USER_ID = "123e4567-e89b-12d3-a456-426614174000";
    private static final UUID USER_UUID = UUID.fromString(USER_ID);

    @Mock
    private FolderService folderService;

    @InjectMocks
    private FolderController controller;

    @Test
    @DisplayName("createFolder: creates root folder and returns 201")
    void createFolder_root_returnsCreated() {
        UUID folderId = UUID.randomUUID();
        Folder folder = folder(folderId, "Documents", USER_UUID, null);
        when(folderService.createFolder("Documents", USER_UUID, null)).thenReturn(folder);

        ResponseEntity<FolderResponse> response = controller.createFolder(new FolderRequest("Documents", null), USER_ID);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(folderId, response.getBody().getFolderId());
        assertEquals("Documents", response.getBody().getFolderName());
        assertNull(response.getBody().getParentFolderId());
        assertEquals(0L, response.getBody().getChildCount());
        assertTrue(response.getBody().getIsActive());
    }

    @Test
    @DisplayName("createFolder: creates child folder with parent id")
    void createFolder_child_passesParentId() {
        UUID parentId = UUID.randomUUID();
        UUID folderId = UUID.randomUUID();
        Folder folder = folder(folderId, "Reports", USER_UUID, parentId);
        when(folderService.createFolder("Reports", USER_UUID, parentId)).thenReturn(folder);

        ResponseEntity<FolderResponse> response = controller.createFolder(new FolderRequest("Reports", parentId), USER_ID);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(parentId, response.getBody().getParentFolderId());
        verify(folderService).createFolder("Reports", USER_UUID, parentId);
    }

    @Test
    @DisplayName("createFolder: invalid user id is rejected before service call")
    void createFolder_invalidUserId_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> controller.createFolder(new FolderRequest("Documents", null), "not-a-uuid"));
        verifyNoInteractions(folderService);
    }

    @Test
    @DisplayName("createFolder: service exception is rethrown")
    void createFolder_serviceException_rethrows() {
        when(folderService.createFolder("", USER_UUID, null)).thenThrow(new IllegalArgumentException("invalid"));

        assertThrows(IllegalArgumentException.class,
                () -> controller.createFolder(new FolderRequest("", null), USER_ID));
    }

    @Test
    @DisplayName("listFolders: returns non-empty list with child counts")
    void listFolders_nonEmpty_returnsOk() {
        UUID parentId = UUID.randomUUID();
        Folder folder = folder(UUID.randomUUID(), "Parent", USER_UUID, null);
        folder.getChildFolders().add(folder(UUID.randomUUID(), "Child", USER_UUID, folder.getFolderId()));
        when(folderService.listFolders(parentId)).thenReturn(List.of(folder));

        ResponseEntity<List<FolderResponse>> response = controller.listFolders(parentId, USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, response.getBody().size());
        assertEquals(1L, response.getBody().getFirst().getChildCount());
        assertTrue(response.getBody().getFirst().getIsActive());
    }

    @Test
    @DisplayName("listFolders: returns empty list")
    void listFolders_empty_returnsOk() {
        when(folderService.listFolders(null)).thenReturn(List.of());

        ResponseEntity<List<FolderResponse>> response = controller.listFolders(null, USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().isEmpty());
    }

    @Test
    @DisplayName("getFolderById: active folder returns 200")
    void getFolderById_active_returnsOk() {
        UUID folderId = UUID.randomUUID();
        Folder folder = folder(folderId, "Documents", USER_UUID, null);
        folder.getChildFolders().add(folder(UUID.randomUUID(), "Child", USER_UUID, folderId));
        when(folderService.getFolderByIdOrThrow(folderId)).thenReturn(folder);

        ResponseEntity<FolderResponse> response = controller.getFolderById(folderId, USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(folderId, response.getBody().getFolderId());
        assertEquals(1L, response.getBody().getChildCount());
    }

    @Test
    @DisplayName("getFolderById: deleted folder returns 410 Gone")
    void getFolderById_deleted_returnsGone() {
        UUID folderId = UUID.randomUUID();
        Folder folder = folder(folderId, "Deleted", USER_UUID, null).softDelete();
        when(folderService.getFolderByIdOrThrow(folderId)).thenReturn(folder);

        ResponseEntity<FolderResponse> response = controller.getFolderById(folderId, USER_ID);

        assertEquals(HttpStatus.GONE, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("getFolderById: not found exception is rethrown")
    void getFolderById_notFound_rethrows() {
        UUID folderId = UUID.randomUUID();
        FolderNotFoundException exception = new FolderNotFoundException(folderId);
        when(folderService.getFolderByIdOrThrow(folderId)).thenThrow(exception);

        FolderNotFoundException thrown = assertThrows(FolderNotFoundException.class,
                () -> controller.getFolderById(folderId, USER_ID));
        assertSame(exception, thrown);
    }

    @Test
    @DisplayName("updateFolder: renamed folder returns 200")
    void updateFolder_success_returnsOk() {
        UUID folderId = UUID.randomUUID();
        Folder folder = folder(folderId, "Updated", USER_UUID, null);
        when(folderService.renameFolder(folderId, "Updated")).thenReturn(folder);

        ResponseEntity<FolderResponse> response = controller.updateFolder(folderId, new FolderRequest("Updated", null), USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Updated", response.getBody().getFolderName());
        assertTrue(response.getBody().getIsActive());
    }

    @Test
    @DisplayName("updateFolder: not found exception is rethrown")
    void updateFolder_notFound_rethrows() {
        UUID folderId = UUID.randomUUID();
        FolderNotFoundException exception = new FolderNotFoundException(folderId);
        when(folderService.renameFolder(folderId, "Missing")).thenThrow(exception);

        FolderNotFoundException thrown = assertThrows(FolderNotFoundException.class,
                () -> controller.updateFolder(folderId, new FolderRequest("Missing", null), USER_ID));
        assertSame(exception, thrown);
    }

    @Test
    @DisplayName("updateFolder: invalid name exception is rethrown")
    void updateFolder_invalidName_rethrows() {
        UUID folderId = UUID.randomUUID();
        InvalidFolderNameException exception = new InvalidFolderNameException("invalid");
        when(folderService.renameFolder(folderId, " ")).thenThrow(exception);

        InvalidFolderNameException thrown = assertThrows(InvalidFolderNameException.class,
                () -> controller.updateFolder(folderId, new FolderRequest(" ", null), USER_ID));
        assertSame(exception, thrown);
    }

    @Test
    @DisplayName("deleteFolder: soft delete returns 200 with deletion timestamp")
    void deleteFolder_success_returnsOk() {
        UUID folderId = UUID.randomUUID();
        Folder folder = folder(folderId, "Deleted", USER_UUID, null).softDelete();
        when(folderService.getFolderByIdOrThrow(folderId)).thenReturn(folder);

        ResponseEntity<FolderDeleteResponse> response = controller.deleteFolder(folderId, USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(folderId, response.getBody().getFolderId());
        assertNotNull(response.getBody().getDeletedAt());
        assertEquals("Folder deleted successfully", response.getBody().getMessage());
        verify(folderService).softDeleteFolder(folderId);
    }

    @Test
    @DisplayName("deleteFolder: soft delete not found exception is rethrown")
    void deleteFolder_softDeleteNotFound_rethrows() {
        UUID folderId = UUID.randomUUID();
        FolderNotFoundException exception = new FolderNotFoundException(folderId);
        doThrow(exception).when(folderService).softDeleteFolder(folderId);

        FolderNotFoundException thrown = assertThrows(FolderNotFoundException.class,
                () -> controller.deleteFolder(folderId, USER_ID));
        assertSame(exception, thrown);
    }

    @Test
    @DisplayName("deleteFolder: lookup after delete not found exception is rethrown")
    void deleteFolder_lookupAfterDeleteNotFound_rethrows() {
        UUID folderId = UUID.randomUUID();
        FolderNotFoundException exception = new FolderNotFoundException(folderId);
        when(folderService.getFolderByIdOrThrow(folderId)).thenThrow(exception);

        FolderNotFoundException thrown = assertThrows(FolderNotFoundException.class,
                () -> controller.deleteFolder(folderId, USER_ID));
        assertSame(exception, thrown);
    }

    private static Folder folder(UUID folderId, String name, UUID ownerId, UUID parentId) {
        Folder folder = new Folder(name, ownerId, parentId);
        folder.setFolderId(folderId);
        return folder;
    }
}
