package pt.isep.desofs.enderchest.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * User entity representing a system user with authentication credentials.
 *
 * This entity implements user identity management for the EnderChest collaborative
 * storage system. It tracks user credentials, profile information, and lifecycle.
 *
 * Performance considerations:
 * - email and username are indexed (UNIQUE) for authentication lookups
 * - createdAt indexed for user listing and audit queries
 * - Uses UUID for ID to prevent sequential ID guessing attacks
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Entity
@Table(
    name = "users",
    indexes = {
        @Index(name = "idx_users_email", columnList = "email", unique = true),
        @Index(name = "idx_users_username", columnList = "username", unique = true),
        @Index(name = "idx_users_created_at", columnList = "created_at")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User {

    /**
     * Unique identifier (UUID v4, auto-generated).
     * Using UUID prevents sequential ID enumeration attacks.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "user_id", nullable = false, updatable = false, columnDefinition = "UUID")
    private UUID userId;

    /**
     * Username for user identification and login.
     * Must be unique across the system.
     */
    @NotBlank(message = "Username must not be blank")
    @Column(name = "username", nullable = false, unique = true, length = 100)
    private String username;

    /**
     * Email address for user identification and communication.
     * Must be unique and in valid email format.
     */
    @NotBlank(message = "Email must not be blank")
    @Email(message = "Email must be valid")
    @Column(name = "email", nullable = false, unique = true, length = 255)
    private String email;

    /**
     * Password hash (bcrypt or similar).
     * Never store plaintext passwords.
     */
    @NotBlank(message = "Password hash must not be blank")
    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    /**
     * User's first name.
     */
    @NotBlank(message = "First name must not be blank")
    @Column(name = "first_name", nullable = false, length = 100)
    private String firstName;

    /**
     * User's last name.
     */
    @NotBlank(message = "Last name must not be blank")
    @Column(name = "last_name", nullable = false, length = 100)
    private String lastName;

    /**
     * Timestamp when the user was created.
     * Set automatically by JPA lifecycle hook.
     */
    @NotNull(message = "Created at timestamp must not be null")
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime createdAt;

    /**
     * Timestamp for tracking user updates (metadata changes).
     */
    @Column(name = "updated_at", columnDefinition = "TIMESTAMP WITH TIME ZONE")
    private LocalDateTime updatedAt;

    /**
     * Constructor with essential user metadata.
     *
     * @param username User's unique username
     * @param email User's unique email address
     * @param passwordHash Bcrypt hashed password
     * @param firstName User's first name
     * @param lastName User's last name
     */
    public User(String username, String email, String passwordHash, String firstName, String lastName) {
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    /**
     * JPA @PrePersist hook: Initialize timestamps on creation.
     * Called automatically before the entity is inserted into the database.
     */
    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    /**
     * JPA @PreUpdate hook: Update modification timestamp.
     * Called automatically before the entity is updated in the database.
     */
    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    /**
     * Get the user's full name.
     *
     * @return Concatenated first and last name
     */
    public String getFullName() {
        return this.firstName + " " + this.lastName;
    }
}
