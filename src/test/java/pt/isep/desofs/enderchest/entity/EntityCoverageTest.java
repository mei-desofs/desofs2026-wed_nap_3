package pt.isep.desofs.enderchest.entity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Entity Unit Tests")
class EntityCoverageTest {

    // ── Folder ────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Folder: root constructor and isRootFolder/isActive")
    void folder_rootConstructor() {
        UUID owner = UUID.randomUUID();
        Folder folder = new Folder("Docs", owner);

        assertEquals("Docs", folder.getFolderName());
        assertEquals(owner, folder.getOwnerId());
        assertTrue(folder.isRootFolder());
        assertTrue(folder.isActive());
        assertNotNull(folder.getChildFolders());
        assertTrue(folder.getChildFolders().isEmpty());
    }

    @Test
    @DisplayName("Folder: child constructor sets parent")
    void folder_childConstructor() {
        UUID owner = UUID.randomUUID();
        UUID parent = UUID.randomUUID();
        Folder folder = new Folder("Sub", owner, parent);

        assertEquals(parent, folder.getParentFolderId());
        assertFalse(folder.isRootFolder());
    }

    @Test
    @DisplayName("Folder: softDelete then restore toggles active state")
    void folder_softDeleteRestore() {
        Folder folder = new Folder("X", UUID.randomUUID());
        folder.softDelete();
        assertFalse(folder.isActive());
        assertNotNull(folder.getDeletedAt());

        folder.restore();
        assertTrue(folder.isActive());
        assertNull(folder.getDeletedAt());
    }

    @Test
    @DisplayName("Folder: add and remove child folder maintains relationship")
    void folder_addRemoveChild() {
        Folder parent = new Folder("Parent", UUID.randomUUID());
        parent.setFolderId(UUID.randomUUID());
        Folder child = new Folder("Child", UUID.randomUUID());

        parent.addChildFolder(child);
        assertEquals(1, parent.getChildFolders().size());
        assertEquals(parent.getFolderId(), child.getParentFolderId());

        parent.removeChildFolder(child);
        assertTrue(parent.getChildFolders().isEmpty());
        assertNull(child.getParentFolderId());
    }

    @Test
    @DisplayName("Folder: setters update fields")
    void folder_setters() {
        Folder folder = new Folder();
        UUID id = UUID.randomUUID();
        folder.setFolderId(id);
        folder.setFolderName("Renamed");
        assertEquals(id, folder.getFolderId());
        assertEquals("Renamed", folder.getFolderName());
    }

    // ── File ────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("File: constructor, softDelete/delete/restore, isActive")
    void file_lifecycle() {
        File file = new File("orig.txt", "stored.txt", "hash123", 100L, "text/plain", "user@example.com", "/loc");
        assertTrue(file.isActive());
        assertEquals("orig.txt", file.getOriginalFileName());
        assertEquals(100L, file.getFileSize());

        file.softDelete();
        assertFalse(file.isActive());
        assertNotNull(file.getDeletedAt());

        file.restore();
        assertTrue(file.isActive());

        file.delete(); // deprecated alias
        assertFalse(file.isActive());
    }

    @Test
    @DisplayName("File: setters update fields")
    void file_setters() {
        File file = new File();
        UUID id = UUID.randomUUID();
        file.setId(id);
        file.setMimeType("image/png");
        assertEquals(id, file.getId());
        assertEquals("image/png", file.getMimeType());
    }

    // ── FileVersion ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("FileVersion: isInitialVersion and isSameContent")
    void fileVersion_logic() {
        File file = new File("o.txt", "s.txt", "h", 1L, "text/plain", "u", "/l");
        FileVersion v1 = new FileVersion(file, 1, "hashA", "user", "initial");
        FileVersion v2 = new FileVersion(file, 2, "hashA", "user", "same content");
        FileVersion v3 = new FileVersion(file, 3, "hashB", "user", "changed");

        assertTrue(v1.isInitialVersion());
        assertFalse(v2.isInitialVersion());
        assertTrue(v1.isSameContent(v2));
        assertFalse(v1.isSameContent(v3));
        assertEquals(2, v2.getVersionNumber());
    }

    // ── AccessShare ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("AccessShare: owner role permissions")
    void accessShare_owner() {
        AccessShare share = new AccessShare(UUID.randomUUID(), AccessShare.ResourceType.FILE,
                UUID.randomUUID(), AccessShare.RoleType.OWNER);
        assertTrue(share.isOwner());
        assertTrue(share.canEdit());
        assertTrue(share.canView());
    }

    @Test
    @DisplayName("AccessShare: editor role permissions")
    void accessShare_editor() {
        AccessShare share = new AccessShare(UUID.randomUUID(), AccessShare.ResourceType.FOLDER,
                UUID.randomUUID(), AccessShare.RoleType.EDITOR);
        assertFalse(share.isOwner());
        assertTrue(share.canEdit());
        assertTrue(share.canView());
        assertEquals(AccessShare.ResourceType.FOLDER, share.getResourceType());
    }

    @Test
    @DisplayName("AccessShare: viewer role permissions")
    void accessShare_viewer() {
        AccessShare share = new AccessShare(UUID.randomUUID(), AccessShare.ResourceType.FILE,
                UUID.randomUUID(), AccessShare.RoleType.VIEWER);
        assertFalse(share.isOwner());
        assertFalse(share.canEdit());
        assertTrue(share.canView());
    }

    // ── User ────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("User: constructor and getFullName")
    void user_fullName() {
        User user = new User("jdoe", "jdoe@example.com", "hash", "John", "Doe");
        assertEquals("John Doe", user.getFullName());
        assertEquals("jdoe", user.getUsername());
        assertEquals("jdoe@example.com", user.getEmail());
    }

    // ── AuditLog ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("AuditLog: constructor and constants")
    void auditLog_construct() {
        UUID resourceId = UUID.randomUUID();
        AuditLog log = new AuditLog(AuditLog.Action.FILE_UPLOAD, "user-1",
                AuditLog.ResourceType.FILE, resourceId, "{\"k\":\"v\"}", "127.0.0.1");

        assertEquals(AuditLog.Action.FILE_UPLOAD, log.getAction());
        assertEquals("user-1", log.getUserId());
        assertEquals(AuditLog.ResourceType.FILE, log.getResourceType());
        assertEquals(resourceId, log.getResourceId());
        assertEquals("127.0.0.1", log.getIpAddress());
        assertEquals("FILE_DOWNLOAD", AuditLog.Action.FILE_DOWNLOAD);
        assertEquals("FOLDER", AuditLog.ResourceType.FOLDER);
    }
}
