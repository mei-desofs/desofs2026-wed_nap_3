package pt.isep.desofs.enderchest.controller;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import pt.isep.desofs.enderchest.entity.AccessShare;
import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.entity.User;
import pt.isep.desofs.enderchest.repository.AccessShareRepository;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.repository.UserRepository;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ST-02 — IDOR Prevention Integration Tests
 *
 * Verifies that the object-level AccessShare authorisation check prevents
 * Insecure Direct Object Reference (IDOR) attacks on file endpoints.
 *
 * Abuse Case:  AC-04 — IDOR: Access Another User's Files
 * Threat:      T-07  — IDOR: Object-Level Authorisation Bypass
 * Requirement: SDR-02 — RBAC object-level check per operation
 *
 * Test Scenarios:
 * - User B cannot download User A's file without an AccessShare record → 403
 * - User B cannot delete  User A's file without an AccessShare record → 403
 * - User A (the uploader) can always download and delete their own file
 * - User B with VIEWER AccessShare can download  → 404 (IDOR passed, no file on disk)
 * - User B with EDITOR AccessShare can download  → 404 (IDOR passed, no file on disk)
 * - User B with VIEWER AccessShare cannot delete → 403
 * - User B with EDITOR AccessShare cannot delete → 403
 * - User B with OWNER  AccessShare can delete    → 200
 * - Unauthenticated requests                     → 401
 *
 * Uses jwt() post-processor (real Jwt principal with sub + email claims)
 * instead of @WithMockUser — matches Auth0 JWT structure used in production.
 * Uses H2 in-memory DB (application-test.properties) — no PostgreSQL needed.
 *
 * @author Developer 4 — Bug Hunter & Documenter
 * @version 1.0
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("ST-02 — IDOR Prevention Tests")
class FileAccessControlIT {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private FileRepository fileRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AccessShareRepository accessShareRepository;

    // ── Test data ──────────────────────────────────────────────────────────────

    // User A is the uploader — JWT sub matches uploadedBy in the File entity
    private static final String USER_A_SUB   = "userA-sub";
    private static final String USER_A_EMAIL = "userA@test.com";

    // User B is the attacker / second user trying to access User A's file
    private static final String USER_B_SUB   = "userB-sub";
    private static final String USER_B_EMAIL = "userB@test.com";

    private UUID fileId;
    private UUID userBId;

    /**
     * Before each test:
     * 1. Create User B in the DB — needed for resolveUserUuid() in FileController,
     *    which looks up the User by email claim to get their internal UUID for the
     *    AccessShare lookup.
     * 2. Persist a File owned by User A directly into the DB — bypasses the upload
     *    endpoint entirely. storageLocation points to a non-existent path on purpose:
     *    the IDOR check fires BEFORE any filesystem access, so 403 is returned before
     *    the app tries to read the file from disk.
     */
    @BeforeEach
    void setUp() {
        User userB = new User(
                "userB",
                USER_B_EMAIL,
                "$2a$10$irrelevant-hash-for-tests",
                "User",
                "B"
        );
        userBId = userRepository.save(userB).getUserId();

        File fileOwnedByUserA = new File(
                "secret-document.pdf",
                UUID.randomUUID().toString(),
                "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
                1024L,
                "application/pdf",
                USER_A_SUB,
                "/tmp/non-existent-path/" + UUID.randomUUID()
        );
        fileId = fileRepository.save(fileOwnedByUserA).getId();
    }

    /**
     * Clean up DB after each test to keep tests fully independent.
     */
    @AfterEach
    void tearDown() {
        accessShareRepository.deleteAll();
        fileRepository.deleteAll();
        userRepository.deleteAll();
    }

    // ── Helper: build a real JWT mock with subject + email + role ──────────────

    /**
     * Creates a JWT post-processor mimicking what Auth0 sends:
     * - sub   = user identity (used by uploadedBy check in FileController)
     * - email = used by resolveUserUuid() to find the User entity in DB
     * - role  = Spring Security authority for @PreAuthorize
     */
    private org.springframework.test.web.servlet.request.RequestPostProcessor jwtFor(
            String sub, String email, String role) {
        return jwt()
                .jwt(j -> j.subject(sub).claim("email", email))
                .authorities(new SimpleGrantedAuthority(role));
    }

    // ── Helper: persist an AccessShare with createdAt set manually ─────────────

    /**
     * AccessShare has @NotNull on createdAt but relies on @CreationTimestamp (Hibernate)
     * to set it. Bean Validation runs before Hibernate lifecycle hooks, causing a
     * ConstraintViolationException if createdAt is null. Set it manually here.
     */
    private void grantAccess(AccessShare.RoleType role) {
        AccessShare share = new AccessShare(
                fileId,
                AccessShare.ResourceType.FILE,
                userBId,
                role
        );
        share.setCreatedAt(LocalDateTime.now());
        accessShareRepository.save(share);
    }

    // ── DOWNLOAD tests ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-02-01: User B cannot download User A's file — no AccessShare → 403 Forbidden")
    void userB_cannot_download_userA_file_without_access_share() throws Exception {
        mockMvc.perform(get("/api/v1/files/" + fileId)
                        .with(jwtFor(USER_B_SUB, USER_B_EMAIL, "ROLE_OWNER")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ST-02-02: User A can download their own file — uploader check passes → 404 (IDOR passed, no file on disk)")
    void userA_can_download_own_file() throws Exception {
        // 404 means IDOR guard passed and app tried to serve the file — file not on disk is expected
        mockMvc.perform(get("/api/v1/files/" + fileId)
                        .with(jwtFor(USER_A_SUB, USER_A_EMAIL, "ROLE_OWNER")))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("ST-02-03: User B with VIEWER AccessShare can download → 404 (IDOR passed, no file on disk)")
    void userB_with_viewer_access_share_can_download() throws Exception {
        grantAccess(AccessShare.RoleType.VIEWER);

        mockMvc.perform(get("/api/v1/files/" + fileId)
                        .with(jwtFor(USER_B_SUB, USER_B_EMAIL, "ROLE_VIEWER")))
                .andExpect(status().isNotFound()); // 404 = IDOR passed ✅
    }

    @Test
    @DisplayName("ST-02-04: User B with EDITOR AccessShare can download → 404 (IDOR passed, no file on disk)")
    void userB_with_editor_access_share_can_download() throws Exception {
        grantAccess(AccessShare.RoleType.EDITOR);

        mockMvc.perform(get("/api/v1/files/" + fileId)
                        .with(jwtFor(USER_B_SUB, USER_B_EMAIL, "ROLE_EDITOR")))
                .andExpect(status().isNotFound()); // 404 = IDOR passed ✅
    }

    // ── DELETE tests ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-02-05: User B cannot delete User A's file — no AccessShare → 403 Forbidden")
    void userB_cannot_delete_userA_file_without_access_share() throws Exception {
        mockMvc.perform(delete("/api/v1/files/" + fileId)
                        .with(jwtFor(USER_B_SUB, USER_B_EMAIL, "ROLE_OWNER")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ST-02-06: User A can delete their own file — uploader check passes → 200")
    void userA_can_delete_own_file() throws Exception {
        mockMvc.perform(delete("/api/v1/files/" + fileId)
                        .with(jwtFor(USER_A_SUB, USER_A_EMAIL, "ROLE_OWNER")))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("ST-02-07: User B with VIEWER AccessShare cannot delete — VIEWER not enough for delete → 403")
    void userB_with_viewer_access_share_cannot_delete() throws Exception {
        grantAccess(AccessShare.RoleType.VIEWER);

        mockMvc.perform(delete("/api/v1/files/" + fileId)
                        .with(jwtFor(USER_B_SUB, USER_B_EMAIL, "ROLE_OWNER")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ST-02-08: User B with EDITOR AccessShare cannot delete — EDITOR not enough for delete → 403")
    void userB_with_editor_access_share_cannot_delete() throws Exception {
        grantAccess(AccessShare.RoleType.EDITOR);

        mockMvc.perform(delete("/api/v1/files/" + fileId)
                        .with(jwtFor(USER_B_SUB, USER_B_EMAIL, "ROLE_OWNER")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ST-02-09: User B with OWNER AccessShare can delete User A's file → 200")
    void userB_with_owner_access_share_can_delete() throws Exception {
        grantAccess(AccessShare.RoleType.OWNER);

        mockMvc.perform(delete("/api/v1/files/" + fileId)
                        .with(jwtFor(USER_B_SUB, USER_B_EMAIL, "ROLE_OWNER")))
                .andExpect(status().isOk());
    }

    // ── Unauthenticated tests ───────────────────────────────────────────────────

    @Test
    @DisplayName("ST-02-10: Unauthenticated download → 401 Unauthorized (before IDOR check)")
    void unauthenticated_cannot_download() throws Exception {
        mockMvc.perform(get("/api/v1/files/" + fileId))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("ST-02-11: Unauthenticated delete → 401 Unauthorized (before IDOR check)")
    void unauthenticated_cannot_delete() throws Exception {
        mockMvc.perform(delete("/api/v1/files/" + fileId))
                .andExpect(status().isUnauthorized());
    }
}
