package pt.isep.desofs.enderchest.exception.security;

/**
 * Exception thrown when API rate limit is exceeded.
 * 
 * This exception is thrown when:
 * - User exceeds maximum requests per time window
 * - Request rate exceeds configured limit
 * 
 * Response: HTTP 429 Too Many Requests
 * 
 * The exception does not expose details about rate limit thresholds
 * (security best practice: prevent rate limit enumeration).
 * 
 * @author Backend Architecture
 * @version 1.0
 */
public class RateLimitException extends RuntimeException {
    
    private final String userId;
    private final long retryAfterSeconds;
    
    /**
     * Create exception with user ID and retry-after time.
     * 
     * @param userId The user ID that exceeded rate limit
     * @param retryAfterSeconds Suggested wait time before retry
     */
    public RateLimitException(String userId, long retryAfterSeconds) {
        super(String.format(
            "Rate limit exceeded for user: %s. Retry after %d seconds",
            userId, retryAfterSeconds
        ));
        this.userId = userId;
        this.retryAfterSeconds = retryAfterSeconds;
    }
    
    /**
     * Create exception with custom message.
     * 
     * @param message Detailed error message
     */
    public RateLimitException(String message) {
        super(message);
        this.userId = null;
        this.retryAfterSeconds = 0;
    }
    
    public String getUserId() {
        return userId;
    }
    
    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
