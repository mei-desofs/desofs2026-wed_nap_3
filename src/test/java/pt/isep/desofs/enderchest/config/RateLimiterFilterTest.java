package pt.isep.desofs.enderchest.config;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@DisplayName("RateLimiterFilter Unit Tests")
class RateLimiterFilterTest {

    private final ApplicationProperties properties = new ApplicationProperties(
            new ApplicationProperties.Storage("/tmp", "10MB", java.util.Set.of("image/png"), "1GB"),
            new ApplicationProperties.RateLimit(3, 60));

    private final RateLimiterFilter filter = new RateLimiterFilter(properties);

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
        filter.resetAll();
    }

    private void authenticateAs(String userId) {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                userId, "n/a", List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    @Test
    @DisplayName("Anonymous authentication passes through without rate limiting")
    void anonymous_passesThrough() throws Exception {
        AnonymousAuthenticationToken anon = new AnonymousAuthenticationToken(
                "key", "anonymousUser", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
        SecurityContextHolder.getContext().setAuthentication(anon);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("Null authentication passes through")
    void nullAuth_passesThrough() throws Exception {
        SecurityContextHolder.clearContext();
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("Blank username passes through")
    void blankUser_passesThrough() throws Exception {
        authenticateAs("");
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("Authenticated requests under the limit pass through")
    void underLimit_passesThrough() throws Exception {
        authenticateAs("user-under");
        FilterChain chain = mock(FilterChain.class);

        for (int i = 0; i < 3; i++) {
            filter.doFilterInternal(new MockHttpServletRequest(), new MockHttpServletResponse(), chain);
        }

        verify(chain, times(3)).doFilter(any(), any());
    }

    @Test
    @DisplayName("Exceeding the limit returns HTTP 429 with Retry-After header")
    void overLimit_returns429() throws Exception {
        authenticateAs("user-over");
        FilterChain chain = mock(FilterChain.class);

        for (int i = 0; i < 3; i++) {
            filter.doFilterInternal(new MockHttpServletRequest(), new MockHttpServletResponse(), chain);
        }
        MockHttpServletResponse blocked = new MockHttpServletResponse();
        filter.doFilterInternal(new MockHttpServletRequest(), blocked, chain);

        assertEquals(429, blocked.getStatus());
        assertNotNull(blocked.getHeader("Retry-After"));
        assertTrue(blocked.getContentAsString().contains("Too Many Requests"));
        verify(chain, times(3)).doFilter(any(), any());
    }

    @Test
    @DisplayName("resetUser clears state for a specific user")
    void resetUser_clearsState() throws Exception {
        authenticateAs("user-reset");
        FilterChain chain = mock(FilterChain.class);
        for (int i = 0; i < 3; i++) {
            filter.doFilterInternal(new MockHttpServletRequest(), new MockHttpServletResponse(), chain);
        }
        filter.resetUser("user-reset");

        MockHttpServletResponse afterReset = new MockHttpServletResponse();
        filter.doFilterInternal(new MockHttpServletRequest(), afterReset, chain);

        assertEquals(200, afterReset.getStatus());
    }
}
