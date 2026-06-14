package pt.isep.desofs.enderchest.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import pt.isep.desofs.enderchest.config.RateLimiterFilter;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ST-10 — Rate Limiter Integration Tests (SDR-10)
 *
 * Verifies that the sliding-window rate limiter correctly enforces the
 * 100-requests-per-minute threshold and returns HTTP 429 Too Many Requests
 * once a user exceeds that limit.
 *
 * Test property source overrides the test-profile default (10 000 req/min)
 * to match the production threshold of 100 requests per 60-second window.
 *
 * Per-request user simulation via SecurityMockMvcRequestPostProcessors.user()
 * ensures each test method uses an isolated user identity, preventing counter
 * state from bleeding between test cases.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "enderchest.rate-limit.requests-per-window=100",
        "enderchest.rate-limit.window-seconds=60"
})
@DisplayName("ST-10 — Rate Limiter Integration Tests (SDR-10)")
class RateLimiterIT {

    private static final String ADMIN_HEALTH_URL = "/api/v1/files/admin/health";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RateLimiterFilter rateLimiterFilter;

    @BeforeEach
    void resetRateLimiterState() {
        // Wipe all per-user counters before each test to guarantee isolation
        rateLimiterFilter.resetAll();
    }

    // ─────────────────────────────────────────────────────────────────
    // ST-10-01: Requests within the limit are served normally
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-10-01: First 100 requests within the window return 200 OK")
    void first100RequestsAreServedSuccessfully() throws Exception {
        for (int i = 0; i < 100; i++) {
            mockMvc.perform(get(ADMIN_HEALTH_URL)
                            .with(user("st10-user-01").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                    .andExpect(status().isOk());
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // ST-10-02: 101st request must be rejected with 429
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-10-02: 101st request within the window returns 429 Too Many Requests")
    void requestAfter100ThresholdReturns429() throws Exception {
        for (int i = 0; i < 100; i++) {
            mockMvc.perform(get(ADMIN_HEALTH_URL)
                            .with(user("st10-user-02").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                    .andExpect(status().isOk());
        }

        // The 101st request must be rate-limited
        mockMvc.perform(get(ADMIN_HEALTH_URL)
                        .with(user("st10-user-02").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isTooManyRequests());
    }

    // ─────────────────────────────────────────────────────────────────
    // ST-10-03: 429 response body carries the correct error fields
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-10-03: 429 response body contains status 429 and error message")
    void rateLimitedResponseBodyContainsErrorDetails() throws Exception {
        exhaustLimit("st10-user-03");

        mockMvc.perform(get(ADMIN_HEALTH_URL)
                        .with(user("st10-user-03").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.error").value("Too Many Requests"))
                .andExpect(jsonPath("$.message").exists());
    }

    // ─────────────────────────────────────────────────────────────────
    // ST-10-04: Retry-After header is present on rate-limited responses
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-10-04: 429 response includes Retry-After header")
    void rateLimitedResponseIncludesRetryAfterHeader() throws Exception {
        exhaustLimit("st10-user-04");

        mockMvc.perform(get(ADMIN_HEALTH_URL)
                        .with(user("st10-user-04").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
    }

    // ─────────────────────────────────────────────────────────────────
    // ST-10-05: Retry-After value is a positive integer (seconds)
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-10-05: Retry-After header value is a positive integer")
    void retryAfterHeaderValueIsPositiveInteger() throws Exception {
        exhaustLimit("st10-user-05");

        String retryAfter = mockMvc.perform(get(ADMIN_HEALTH_URL)
                        .with(user("st10-user-05").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isTooManyRequests())
                .andReturn()
                .getResponse()
                .getHeader("Retry-After");

        long retryAfterSeconds = Long.parseLong(retryAfter);
        assert retryAfterSeconds >= 1 : "Retry-After must be at least 1 second";
    }

    // ─────────────────────────────────────────────────────────────────
    // ST-10-06: Rate limits are tracked per user (isolation)
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-10-06: Exhausting user-A rate limit does not affect user-B")
    void rateLimitIsPerUserAndDoesNotAffectOtherUsers() throws Exception {
        // Exhaust user-A's limit
        exhaustLimit("st10-user-06a");
        mockMvc.perform(get(ADMIN_HEALTH_URL)
                        .with(user("st10-user-06a").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isTooManyRequests());

        // User-B has a fresh counter and must still be served
        mockMvc.perform(get(ADMIN_HEALTH_URL)
                        .with(user("st10-user-06b").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isOk());
    }

    // ─────────────────────────────────────────────────────────────────
    // ST-10-07: All subsequent requests after limit are also rejected
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-10-07: Multiple requests after the limit all return 429")
    void allRequestsAfterLimitAreRejected() throws Exception {
        exhaustLimit("st10-user-07");

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(get(ADMIN_HEALTH_URL)
                            .with(user("st10-user-07").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                    .andExpect(status().isTooManyRequests());
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // ST-10-08: Unauthenticated requests receive 401, not 429
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-10-08: Unauthenticated requests return 401 Unauthorized, not 429")
    void unauthenticatedRequestsAreNotRateLimited() throws Exception {
        // No .with(user(...)) — genuinely unauthenticated
        mockMvc.perform(get(ADMIN_HEALTH_URL))
                .andExpect(status().isUnauthorized());
    }

    // ─────────────────────────────────────────────────────────────────
    // ST-10-09: Users with different roles are each tracked independently
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ST-10-09: Rate limit applies to all authenticated roles — VIEWER reaches 429 too")
    void rateLimitAppliesToAllRoles() throws Exception {
        for (int i = 0; i < 100; i++) {
            mockMvc.perform(get("/api/v1/files/00000000-0000-0000-0000-000000000099")
                            .with(user("st10-viewer").authorities(new SimpleGrantedAuthority("ROLE_VIEWER"))))
                    .andReturn(); // Accept any status — we only care about the 101st
        }

        mockMvc.perform(get("/api/v1/files/00000000-0000-0000-0000-000000000099")
                        .with(user("st10-viewer").authorities(new SimpleGrantedAuthority("ROLE_VIEWER"))))
                .andExpect(status().isTooManyRequests());
    }

    // ─────────────────────────────────────────────────────────────────
    // Helper
    // ─────────────────────────────────────────────────────────────────

    /** Sends exactly 100 requests as the given user to fill up the rate-limit window. */
    private void exhaustLimit(String username) throws Exception {
        for (int i = 0; i < 100; i++) {
            mockMvc.perform(get(ADMIN_HEALTH_URL)
                    .with(user(username).authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))));
        }
    }
}
