package pt.isep.desofs.enderchest.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pt.isep.desofs.enderchest.entity.AccessShare;
import pt.isep.desofs.enderchest.exception.resource.AccessShareNotFoundException;
import pt.isep.desofs.enderchest.exception.resource.DuplicateAccessShareException;
import pt.isep.desofs.enderchest.repository.AccessShareRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AccessShareService Unit Tests")
class AccessShareServiceTest {

    @Mock
    private AccessShareRepository accessShareRepository;

    @InjectMocks
    private AccessShareService accessShareService;

    // ── createAccessShare ─────────────────────────────────────────────────────

    @Test
    @DisplayName("createAccessShare: new share is persisted and returned")
    void createAccessShare_new_savesCalled() throws DuplicateAccessShareException {
        UUID resourceId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        when(accessShareRepository.findByResourceIdAndResourceTypeAndGrantedToUserId(
                resourceId, AccessShare.ResourceType.FILE, userId))
                .thenReturn(Optional.empty());

        AccessShare saved = new AccessShare(resourceId, AccessShare.ResourceType.FILE, userId, AccessShare.RoleType.VIEWER);
        when(accessShareRepository.save(any())).thenReturn(saved);

        AccessShare result = accessShareService.createAccessShare(
                resourceId, AccessShare.ResourceType.FILE, userId, AccessShare.RoleType.VIEWER);

        assertNotNull(result);
        verify(accessShareRepository).save(any());
    }

    @Test
    @DisplayName("createAccessShare: duplicate share throws DuplicateAccessShareException")
    void createAccessShare_duplicate_throwsAndNeverSaves() {
        UUID resourceId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        AccessShare existing = new AccessShare(resourceId, AccessShare.ResourceType.FILE, userId, AccessShare.RoleType.VIEWER);
        when(accessShareRepository.findByResourceIdAndResourceTypeAndGrantedToUserId(any(), any(), any()))
                .thenReturn(Optional.of(existing));

        assertThrows(DuplicateAccessShareException.class,
                () -> accessShareService.createAccessShare(
                        resourceId, AccessShare.ResourceType.FILE, userId, AccessShare.RoleType.VIEWER));
        verify(accessShareRepository, never()).save(any());
    }

    @Test
    @DisplayName("createAccessShare: FOLDER resource type is persisted correctly")
    void createAccessShare_folderType_savesCalled() throws DuplicateAccessShareException {
        UUID resourceId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        when(accessShareRepository.findByResourceIdAndResourceTypeAndGrantedToUserId(
                resourceId, AccessShare.ResourceType.FOLDER, userId))
                .thenReturn(Optional.empty());
        AccessShare saved = new AccessShare(resourceId, AccessShare.ResourceType.FOLDER, userId, AccessShare.RoleType.EDITOR);
        when(accessShareRepository.save(any())).thenReturn(saved);

        AccessShare result = accessShareService.createAccessShare(
                resourceId, AccessShare.ResourceType.FOLDER, userId, AccessShare.RoleType.EDITOR);

        assertNotNull(result);
        assertEquals(AccessShare.ResourceType.FOLDER, result.getResourceType());
    }

    // ── revokeAccessShare ─────────────────────────────────────────────────────

    @Test
    @DisplayName("revokeAccessShare: found share is deleted")
    void revokeAccessShare_found_deleteCalled() throws AccessShareNotFoundException {
        UUID shareId = UUID.randomUUID();
        AccessShare share = new AccessShare(UUID.randomUUID(), AccessShare.ResourceType.FILE, UUID.randomUUID(), AccessShare.RoleType.VIEWER);
        when(accessShareRepository.findById(shareId)).thenReturn(Optional.of(share));

        accessShareService.revokeAccessShare(shareId);

        verify(accessShareRepository).delete(share);
    }

    @Test
    @DisplayName("revokeAccessShare: missing share throws AccessShareNotFoundException")
    void revokeAccessShare_missing_throws() {
        UUID shareId = UUID.randomUUID();
        when(accessShareRepository.findById(shareId)).thenReturn(Optional.empty());

        assertThrows(AccessShareNotFoundException.class,
                () -> accessShareService.revokeAccessShare(shareId));
        verify(accessShareRepository, never()).delete(any());
    }

    // ── getAccessShareById ────────────────────────────────────────────────────

    @Test
    @DisplayName("getAccessShareById: found share is returned")
    void getAccessShareById_found_returnsShare() throws AccessShareNotFoundException {
        UUID shareId = UUID.randomUUID();
        AccessShare share = new AccessShare(UUID.randomUUID(), AccessShare.ResourceType.FILE, UUID.randomUUID(), AccessShare.RoleType.OWNER);
        when(accessShareRepository.findById(shareId)).thenReturn(Optional.of(share));

        AccessShare result = accessShareService.getAccessShareById(shareId);

        assertNotNull(result);
        assertEquals(AccessShare.RoleType.OWNER, result.getRoleType());
    }

    @Test
    @DisplayName("getAccessShareById: missing share throws AccessShareNotFoundException")
    void getAccessShareById_missing_throws() {
        UUID shareId = UUID.randomUUID();
        when(accessShareRepository.findById(shareId)).thenReturn(Optional.empty());

        assertThrows(AccessShareNotFoundException.class,
                () -> accessShareService.getAccessShareById(shareId));
    }

    // ── listAccessSharesByResourceId ──────────────────────────────────────────

    @Test
    @DisplayName("listAccessSharesByResourceId: returns list from repository")
    void listAccessSharesByResourceId_returnsAll() {
        UUID resourceId = UUID.randomUUID();
        List<AccessShare> shares = List.of(
                new AccessShare(resourceId, AccessShare.ResourceType.FILE, UUID.randomUUID(), AccessShare.RoleType.VIEWER),
                new AccessShare(resourceId, AccessShare.ResourceType.FILE, UUID.randomUUID(), AccessShare.RoleType.EDITOR)
        );
        when(accessShareRepository.findByResourceIdAndResourceType(resourceId, AccessShare.ResourceType.FILE))
                .thenReturn(shares);

        List<AccessShare> result = accessShareService.listAccessSharesByResourceId(resourceId, AccessShare.ResourceType.FILE);

        assertEquals(2, result.size());
    }

    @Test
    @DisplayName("listAccessSharesByResourceId: returns empty list when no shares exist")
    void listAccessSharesByResourceId_empty_returnsEmptyList() {
        UUID resourceId = UUID.randomUUID();
        when(accessShareRepository.findByResourceIdAndResourceType(resourceId, AccessShare.ResourceType.FILE))
                .thenReturn(List.of());

        List<AccessShare> result = accessShareService.listAccessSharesByResourceId(resourceId, AccessShare.ResourceType.FILE);

        assertTrue(result.isEmpty());
    }
}
