package pt.isep.desofs.enderchest.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ST-07 — Authorization Tests (RBAC Enforcement)
 *
 * Verifica que o RBAC está corretamente implementado em todos os endpoints:
 * - Admin health: apenas ADMIN (200), todos os outros (403), não autenticado (401)
 * - Download: OWNER, EDITOR, VIEWER (tentativa de acesso), não autenticado (401)
 * - Delete: apenas OWNER, EDITOR e VIEWER recebem 403
 *
 * Usa @WithMockUser para simular utilizadores autenticados sem necessitar
 * de um JWT real do Auth0 — os testes são independentes do IdP.
 *
 * Mitiga: SDR-02 (RBAC), T-09 (Role Abuse), T-10 (Unauthorized Admin Access)
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("ST-07 — RBAC Authorization Tests")
public class FileControllerAuthTest {

    @Autowired
    private MockMvc mockMvc;

    // ─────────────────────────────────────────────────────────────────
    // GET /api/v1/files/admin/health — apenas ADMIN
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-07-01: ADMIN acede ao admin/health — deve retornar 200 OK")
    @WithMockUser(authorities = "ROLE_ADMIN")
    void admin_can_access_admin_health() throws Exception {
        mockMvc.perform(get("/api/v1/files/admin/health"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("ST-07-02: OWNER não pode aceder ao admin/health — deve retornar 403 Forbidden")
    @WithMockUser(authorities = "ROLE_OWNER")
    void owner_cannot_access_admin_health() throws Exception {
        mockMvc.perform(get("/api/v1/files/admin/health"))
                .andDo(print())  // <-- adiciona esta linha
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ST-07-03: EDITOR não pode aceder ao admin/health — deve retornar 403 Forbidden")
    @WithMockUser(authorities = "ROLE_EDITOR")
    void editor_cannot_access_admin_health() throws Exception {
        mockMvc.perform(get("/api/v1/files/admin/health"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ST-07-04: VIEWER não pode aceder ao admin/health — deve retornar 403 Forbidden")
    @WithMockUser(authorities = "ROLE_VIEWER")
    void viewer_cannot_access_admin_health() throws Exception {
        mockMvc.perform(get("/api/v1/files/admin/health"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ST-07-05: Utilizador não autenticado recebe 401 Unauthorized")
    void unauthenticated_user_receives_401_on_admin_health() throws Exception {
        mockMvc.perform(get("/api/v1/files/admin/health"))
                .andExpect(status().isUnauthorized());
    }

    // ─────────────────────────────────────────────────────────────────
    // DELETE /api/v1/files/{fileId} — apenas OWNER pode eliminar
    // Demonstra AC-07 / T-09: Editor não pode eliminar ficheiros
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-07-06: EDITOR não pode eliminar ficheiros — deve retornar 403 Forbidden")
    @WithMockUser(authorities = "ROLE_EDITOR")
    void editor_cannot_delete_file() throws Exception {
        mockMvc.perform(delete("/api/v1/files/00000000-0000-0000-0000-000000000001")
                        .header("X-User-Id", "editor@test.com"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ST-07-07: VIEWER não pode eliminar ficheiros — deve retornar 403 Forbidden")
    @WithMockUser(authorities = "ROLE_VIEWER")
    void viewer_cannot_delete_file() throws Exception {
        mockMvc.perform(delete("/api/v1/files/00000000-0000-0000-0000-000000000001")
                        .header("X-User-Id", "viewer@test.com"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ST-07-08: Utilizador não autenticado não pode eliminar ficheiros — deve retornar 401")
    void unauthenticated_cannot_delete_file() throws Exception {
        mockMvc.perform(delete("/api/v1/files/00000000-0000-0000-0000-000000000001"))
                .andExpect(status().isUnauthorized());
    }

    // ─────────────────────────────────────────────────────────────────
    // GET /api/v1/files/{fileId} — OWNER, EDITOR, VIEWER podem descarregar
    // Utilizador não autenticado recebe 401
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-07-09: Utilizador não autenticado não pode descarregar ficheiros — deve retornar 401")
    void unauthenticated_cannot_download_file() throws Exception {
        mockMvc.perform(get("/api/v1/files/00000000-0000-0000-0000-000000000001"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("ST-07-10: ADMIN não pode eliminar ficheiros de utilizadores — deve retornar 403")
    @WithMockUser(authorities = "ROLE_ADMIN")
    void admin_cannot_access_file_endpoints_without_user_id() throws Exception {
        mockMvc.perform(delete("/api/v1/files/00000000-0000-0000-0000-000000000001")
                        .header("X-User-Id", "admin@test.com"))
                .andExpect(status().isForbidden());
    }
}