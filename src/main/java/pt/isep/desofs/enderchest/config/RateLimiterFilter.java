package pt.isep.desofs.enderchest.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sliding-window rate limiter filter (SDR-10).
 *
 * Tracks authenticated requests per user within a configurable time window.
 * Once a user exceeds the configured request limit the filter writes an HTTP 429
 * response directly — bypassing the dispatcher servlet so the filter chain stops
 * immediately.
 *
 * Unauthenticated / anonymous requests are not rate-limited here; they will be
 * rejected by Spring Security with 401 before reaching any business logic.
 */
@Slf4j
public class RateLimiterFilter extends OncePerRequestFilter {

    private final ApplicationProperties properties;

    // userId → timestamps (epoch ms) of requests inside the current window
    private final ConcurrentHashMap<String, Deque<Long>> requestTimestamps = new ConcurrentHashMap<>();

    public RateLimiterFilter(ApplicationProperties properties) {
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }

        String userId = auth.getName();
        if (userId == null || userId.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        int maxRequests = properties.rateLimit().requestsPerWindow();
        long windowMs = properties.rateLimit().windowSeconds() * 1000L;
        long now = Instant.now().toEpochMilli();

        Deque<Long> timestamps = requestTimestamps.computeIfAbsent(userId, k -> new ArrayDeque<>());

        long retryAfterSeconds;

        synchronized (timestamps) {
            // Evict timestamps that have fallen outside the sliding window
            while (!timestamps.isEmpty() && now - timestamps.peekFirst() >= windowMs) {
                timestamps.pollFirst();
            }

            if (timestamps.size() >= maxRequests) {
                long windowStartMs = timestamps.peekFirst();
                retryAfterSeconds = Math.max(1, (windowMs - (now - windowStartMs)) / 1000);
                log.warn("Rate limit exceeded for user '{}': {} requests in {}s window. Retry after {}s",
                        userId, timestamps.size(), properties.rateLimit().windowSeconds(), retryAfterSeconds);
                writeTooManyRequestsResponse(response, retryAfterSeconds);
                return;
            }

            timestamps.addLast(now);
        }

        filterChain.doFilter(request, response);
    }

    private void writeTooManyRequestsResponse(HttpServletResponse response, long retryAfterSeconds)
            throws IOException {
        response.setStatus(429);
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(
                "{\"status\":429,\"error\":\"Too Many Requests\",\"message\":\"Rate limit exceeded. Please retry later\"}"
        );
    }

    /** Exposed for testing: clears all tracked state for a specific user. */
    public void resetUser(String userId) {
        requestTimestamps.remove(userId);
    }

    /** Exposed for testing: clears all tracked state. */
    public void resetAll() {
        requestTimestamps.clear();
    }
}
