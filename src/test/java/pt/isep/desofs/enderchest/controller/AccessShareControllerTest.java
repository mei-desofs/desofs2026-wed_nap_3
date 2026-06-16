package pt.isep.desofs.enderchest.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import pt.isep.desofs.enderchest.entity.AccessShare;
import pt.isep.desofs.enderchest.exception.resource.AccessShareNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.DuplicateAccessShareException;
import pt.isep.desofs.enderchest.service.AccessShareService;
import pt.isep.desofs.enderchest.service.dto.AccessShareDeleteResponse;
import pt.isep.desofs.enderchest.service.dto.AccessShareRequest;
import pt.isep.desofs.enderchest.service.dto.AccessShareResponse;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AccessShareController Unit Tests")
class AccessShareControllerTest {

    private static final String USER_ID = "123e4567-e89b-12d3-a456-426614174000";

    @Mock
    private AccessShareService accessShareService;

    @InjectMocks
    private AccessShareController controller;

    @Test
    @DisplayName("createAccessShare: valid FILE share returns 201")
    void createAccessShare_file_returnsCreated() {
        UUID resourceId = UUID.randomUUID();
        UUID granteeId = UUID.randomUUID();
        UUID shareId = UUID.randomUUID();
        AccessShare share = share(shareId, resourceId, AccessShare.ResourceType.FILE, granteeId, AccessShare.RoleType.VIEWER);
        when(accessShareService.createAccessShare(resourceId, AccessShare.ResourceType.FILE, granteeId, AccessShare.RoleType.VIEWER))
                .thenReturn(share);

        ResponseEntity<AccessShareResponse> response = controller.createAccessShare(
                new AccessShareRequest(resourceId, "FILE", granteeId, "VIEWER"), USER_ID);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(shareId, response.getBody().getShareId());
        assertEquals("FILE", response.getBody().getResourceType());
        assertEquals("VIEWER", response.getBody().getRoleType());
        assertNull(response.getBody().getRevokedAt());
    }

    @Test
    @DisplayName("createAccessShare: valid FOLDER share returns 201")
    void createAccessShare_folder_returnsCreated() {
        UUID resourceId = UUID.randomUUID();
        UUID granteeId = UUID.randomUUID();
        AccessShare share = share(UUID.randomUUID(), resourceId, AccessShare.ResourceType.FOLDER, granteeId, AccessShare.RoleType.EDITOR);
        when(accessShareService.createAccessShare(resourceId, AccessShare.ResourceType.FOLDER, granteeId, AccessShare.RoleType.EDITOR))
                .thenReturn(share);

        ResponseEntity<AccessShareResponse> response = controller.createAccessShare(
                new AccessShareRequest(resourceId, "FOLDER", granteeId, "EDITOR"), USER_ID);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("FOLDER", response.getBody().getResourceType());
        assertEquals("EDITOR", response.getBody().getRoleType());
    }

    @Test
    @DisplayName("createAccessShare: invalid resource type returns 400")
    void createAccessShare_invalidResourceType_returnsBadRequest() {
        ResponseEntity<AccessShareResponse> response = controller.createAccessShare(
                new AccessShareRequest(UUID.randomUUID(), "PROJECT", UUID.randomUUID(), "VIEWER"), USER_ID);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNull(response.getBody());
        verifyNoInteractions(accessShareService);
    }

    @Test
    @DisplayName("createAccessShare: invalid role type returns 400")
    void createAccessShare_invalidRoleType_returnsBadRequest() {
        ResponseEntity<AccessShareResponse> response = controller.createAccessShare(
                new AccessShareRequest(UUID.randomUUID(), "FILE", UUID.randomUUID(), "READER"), USER_ID);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNull(response.getBody());
        verifyNoInteractions(accessShareService);
    }

    @Test
    @DisplayName("createAccessShare: duplicate share returns 409")
    void createAccessShare_duplicate_returnsConflict() {
        UUID resourceId = UUID.randomUUID();
        UUID granteeId = UUID.randomUUID();
        when(accessShareService.createAccessShare(resourceId, AccessShare.ResourceType.FILE, granteeId, AccessShare.RoleType.VIEWER))
                .thenThrow(new DuplicateAccessShareException(resourceId, granteeId));

        ResponseEntity<AccessShareResponse> response = controller.createAccessShare(
                new AccessShareRequest(resourceId, "FILE", granteeId, "VIEWER"), USER_ID);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("revokeAccessShare: existing share returns 200")
    void revokeAccessShare_success_returnsOk() {
        UUID shareId = UUID.randomUUID();

        ResponseEntity<AccessShareDeleteResponse> response = controller.revokeAccessShare(shareId, USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(shareId, response.getBody().getShareId());
        assertNotNull(response.getBody().getRevokedAt());
        assertEquals("Access share revoked successfully", response.getBody().getMessage());
        verify(accessShareService).revokeAccessShare(shareId);
    }

    @Test
    @DisplayName("revokeAccessShare: missing share returns 404")
    void revokeAccessShare_missing_returnsNotFound() {
        UUID shareId = UUID.randomUUID();
        doThrow(new AccessShareNotFoundException(shareId)).when(accessShareService).revokeAccessShare(shareId);

        ResponseEntity<AccessShareDeleteResponse> response = controller.revokeAccessShare(shareId, USER_ID);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("listAccessShares: non-empty list returns 200")
    void listAccessShares_nonEmpty_returnsOk() {
        UUID resourceId = UUID.randomUUID();
        AccessShare share = share(UUID.randomUUID(), resourceId, AccessShare.ResourceType.FILE, UUID.randomUUID(), AccessShare.RoleType.OWNER);
        when(accessShareService.listAccessSharesByResourceId(resourceId, AccessShare.ResourceType.FILE))
                .thenReturn(List.of(share));

        ResponseEntity<?> response = controller.listAccessShares(resourceId, "FILE", USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertInstanceOf(List.class, response.getBody());
        List<?> body = (List<?>) response.getBody();
        assertEquals(1, body.size());
        AccessShareResponse first = (AccessShareResponse) body.getFirst();
        assertEquals("OWNER", first.getRoleType());
        assertEquals(resourceId, first.getResourceId());
    }

    @Test
    @DisplayName("listAccessShares: empty list returns 200")
    void listAccessShares_empty_returnsOk() {
        UUID resourceId = UUID.randomUUID();
        when(accessShareService.listAccessSharesByResourceId(resourceId, AccessShare.ResourceType.FOLDER))
                .thenReturn(List.of());

        ResponseEntity<?> response = controller.listAccessShares(resourceId, "FOLDER", USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertInstanceOf(List.class, response.getBody());
        assertTrue(((List<?>) response.getBody()).isEmpty());
    }

    @Test
    @DisplayName("listAccessShares: invalid resource type returns 400")
    void listAccessShares_invalidType_returnsBadRequest() {
        ResponseEntity<?> response = controller.listAccessShares(UUID.randomUUID(), "BAD", USER_ID);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNull(response.getBody());
        verifyNoInteractions(accessShareService);
    }

    @Test
    @DisplayName("getAccessShare: existing share returns 200")
    void getAccessShare_success_returnsOk() {
        UUID shareId = UUID.randomUUID();
        UUID resourceId = UUID.randomUUID();
        AccessShare share = share(shareId, resourceId, AccessShare.ResourceType.FILE, UUID.randomUUID(), AccessShare.RoleType.EDITOR);
        when(accessShareService.getAccessShareById(shareId)).thenReturn(share);

        ResponseEntity<AccessShareResponse> response = controller.getAccessShare(shareId, USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(shareId, response.getBody().getShareId());
        assertEquals("EDITOR", response.getBody().getRoleType());
    }

    @Test
    @DisplayName("getAccessShare: missing share returns 404")
    void getAccessShare_missing_returnsNotFound() {
        UUID shareId = UUID.randomUUID();
        when(accessShareService.getAccessShareById(shareId)).thenThrow(new AccessShareNotFoundException(shareId));

        ResponseEntity<AccessShareResponse> response = controller.getAccessShare(shareId, USER_ID);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
    }

    private static AccessShare share(UUID shareId, UUID resourceId, AccessShare.ResourceType resourceType,
                                     UUID granteeId, AccessShare.RoleType roleType) {
        AccessShare share = new AccessShare(resourceId, resourceType, granteeId, roleType);
        share.setShareId(shareId);
        share.setCreatedAt(LocalDateTime.now());
        return share;
    }
}
