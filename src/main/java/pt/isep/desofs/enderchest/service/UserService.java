package pt.isep.desofs.enderchest.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pt.isep.desofs.enderchest.entity.User;
import pt.isep.desofs.enderchest.exception.resource.UserNotFoundException;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.repository.UserRepository;
import pt.isep.desofs.enderchest.service.dto.UserProfileResponse;

import java.util.Optional;
import java.util.UUID;

/**
 * Service layer for user profile and storage management operations.
 *
 * This service provides business logic for:
 * - Retrieving user profile information
 * - Calculating user storage usage from file versions
 * - Verifying user existence
 * - Managing user storage quotas
 *
 * Design Principles:
 * - Storage calculation: Sums all file versions for accurate quota enforcement
 * - User lookup: Resolves by UUID for internal operations
 * - Transactional: All operations are atomic
 * - Performance-optimized: Uses repository indexes for efficient queries
 *
 * Performance Characteristics:
 * - getUserProfile: O(log n) - user lookup + O(m) aggregate query where m = user's files
 * - calculateUsedStorage: O(m) where m = number of user's files (database-level aggregation)
 * - checkUserExists: O(log n) - primary key lookup
 *
 * Storage Quota:
 * - Default quota: 10 GB per user (configurable per tier in production)
 * - Calculated at read time from file versions
 * - Used for quota enforcement during upload
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final FileRepository fileRepository;

    /**
     * Default storage quota per user (in bytes).
     * Equivalent to 10 GB.
     * In production, this would be configurable per user/tier.
     */
    private static final Long DEFAULT_STORAGE_QUOTA = 10L * 1024L * 1024L * 1024L;

    /**
     * Get user profile with storage quota information.
     *
     * Retrieves the user's profile information and calculates current storage usage
     * from file versions. Returns available storage based on default quota.
     *
     * @param userId UUID of the user
     * @return UserProfileResponse with profile and storage information
     * @throws UserNotFoundException if user not found
     */
    @Transactional(readOnly = true)
    @NonNull
    public UserProfileResponse getUserProfile(@NonNull UUID userId) throws UserNotFoundException {

        // Retrieve user
        Optional<User> userOptional = userRepository.findById(userId);

        if (userOptional.isEmpty()) {
            log.warn("User not found. UserId: {}", userId);
            throw new UserNotFoundException(userId);
        }

        User user = userOptional.get();

        // Calculate storage usage
        long usedStorage = calculateUsedStorage(userId);

        // Calculate available storage
        long availableStorage = DEFAULT_STORAGE_QUOTA - usedStorage;

        log.info("User profile retrieved. UserId: {}, UsedStorage: {} bytes, AvailableStorage: {} bytes",
                userId, usedStorage, availableStorage);

        // Build response
        return new UserProfileResponse(
                user.getUserId(),
                user.getUsername(),
                user.getEmail(),
                user.getFullName(),
                DEFAULT_STORAGE_QUOTA,
                usedStorage,
                availableStorage
        );
    }

    /**
     * Calculate total storage used by a user.
     *
     * Sums the size of all active file versions owned by the user.
     * This is an O(m) operation where m is the number of user's files,
     * but performed at the database level for efficiency.
     *
     * @param userId UUID of the user
     * @return Total storage used in bytes (0 if user has no files)
     */
    @Transactional(readOnly = true)
    long calculateUsedStorage(@NonNull UUID userId) {

        // Use repository query to calculate storage at database level
        Long usedStorage = fileRepository.calculateUserStorageUsage(userId);

        return usedStorage != null ? usedStorage : 0L;
    }

    /**
     * Check if a user exists by UUID.
     *
     * Useful for verifying user existence before operations.
     *
     * @param userId UUID of the user to check
     * @return true if user exists, false otherwise
     */
    @Transactional(readOnly = true)
    public boolean checkUserExists(@NonNull UUID userId) {

        boolean exists = userRepository.existsById(userId);

        log.debug("User existence check. UserId: {}, Exists: {}", userId, exists);

        return exists;
    }

    /**
     * Get user profile by email.
     *
     * Retrieves the user's profile information by email address and calculates
     * current storage usage. Useful for OAuth/JWT authentication workflows
     * where email is the primary identifier.
     *
     * @param email Email address of the user
     * @return UserProfileResponse with profile and storage information
     * @throws UserNotFoundException if user not found
     */
    @Transactional(readOnly = true)
    @NonNull
    public UserProfileResponse getUserProfileByEmail(@NonNull String email) throws UserNotFoundException {

        // Retrieve user by email
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            log.warn("User not found by email. Email: {}", email);
            throw new UserNotFoundException("User not found: " + email);
        }

        User user = userOptional.get();

        // Calculate storage usage
        long usedStorage = calculateUsedStorage(user.getUserId());

        // Calculate available storage
        long availableStorage = DEFAULT_STORAGE_QUOTA - usedStorage;

        log.info("User profile retrieved by email. UserId: {}, Email: {}, UsedStorage: {} bytes",
                user.getUserId(), email, usedStorage);

        // Build response
        return new UserProfileResponse(
                user.getUserId(),
                user.getUsername(),
                user.getEmail(),
                user.getFullName(),
                DEFAULT_STORAGE_QUOTA,
                usedStorage,
                availableStorage
        );
    }
}
