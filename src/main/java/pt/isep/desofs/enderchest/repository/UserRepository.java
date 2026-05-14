package pt.isep.desofs.enderchest.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pt.isep.desofs.enderchest.entity.User;

import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for User entity.
 *
 * Provides data access layer for user authentication and user management operations.
 * Supports lookups by email and username for authentication purposes.
 *
 * All queries are optimized for authentication workflows and are backed by
 * unique indexes for O(log n) performance.
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    /**
     * Find a user by email address.
     *
     * Used for authentication and account lookup during login flow.
     * Query execution time: O(log n) with unique index on email.
     *
     * @param email The user's email address
     * @return Optional containing the User if found, empty otherwise
     */
    Optional<User> findByEmail(String email);

    /**
     * Find a user by username.
     *
     * Used for authentication and user identification lookups.
     * Query execution time: O(log n) with unique index on username.
     *
     * @param username The user's unique username
     * @return Optional containing the User if found, empty otherwise
     */
    Optional<User> findByUsername(String username);
}
