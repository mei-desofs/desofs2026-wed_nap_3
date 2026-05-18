package pt.isep.desofs.enderchest.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pt.isep.desofs.enderchest.entity.AccessShare;
import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.entity.User;
import pt.isep.desofs.enderchest.exception.resource.FileNotFoundException;
import pt.isep.desofs.enderchest.exception.security.FileAccessDeniedException;
import pt.isep.desofs.enderchest.repository.AccessShareRepository;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.repository.UserRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Service layer for file operations (download, delete).
 *
 * This service provides business logic for:
 * - Downloading files with access control verification
 * - Deleting files (soft delete) with ownership verification
 * - Access control enforcement (IDOR prevention)
 *
 * Design Principles:
 * - Authorization checks: Verifies caller has access before operations
 * - IDOR prevention: Checks file ownership and access shares
 * - Soft delete only: Maintains audit trail
 * - Transactional: All write operations are atomic
 * - Performance-optimized: Uses repository indexes for efficient queries
 *
 * Security:
 * - Read access: Caller is owner OR has AccessShare record
 * - Write access: Caller is owner OR has OWNER-level AccessShare
 * - IDOR check: Validates caller identity before any operation
 *
 * Performance Characteristics:
 * - downloadFile: O(log n + 1) - file lookup + access check
 * - deleteFile: O(log n + 1) - file lookup + access check + soft delete
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class FileService {

    private final FileRepository fileRepository;
    private final AccessShareRepository accessShareRepository;
    private final UserRepository userRepository;

    /**
     * Download a file with access control verification.
     *
     * Verifies that the caller has read access to the file before allowing download.
     * Read access is granted if:
     * 1. Caller is the uploader (owner by creation), OR
     * 2. Caller has an AccessShare record for this file
     *
     * @param fileId UUID of the file to download
     * @param userId User ID from JWT subject to verify caller identity
     * @return File entity if access is granted
     * @throws FileNotFoundException if file not found or is deleted
     * @throws FileAccessDeniedException if caller lacks read access
     */
    @Transactional(readOnly = true)
    @NonNull
    public File downloadFile(@NonNull UUID fileId, @NonNull String userId, String email) throws FileNotFoundException, FileAccessDeniedException {

        // Retrieve file
        Optional<File> fileOptional = fileRepository.findById(fileId);

        if (fileOptional.isEmpty()) {
            log.warn("File not found for download. FileId: {}", fileId);
            throw new FileNotFoundException(fileId);
        }

        File file = fileOptional.get();

        if (file.getIsDeleted()) {
            log.warn("File has been deleted. FileId: {}", fileId);
            throw new FileNotFoundException("File has been deleted: " + fileId);
        }

        // Check read access (IDOR prevention)
        if (!hasReadAccess(file, userId, email)) {
            log.warn("IDOR attempt blocked: user {} attempted to access file {} without permission",
                    userId, fileId);
            throw new FileAccessDeniedException(fileId, null);
        }

        log.info("File download verified. FileId: {}, Caller: {}", fileId, userId);

        return file;
    }

    /**
     * Delete a file (soft delete) with access control verification.
     *
     * Verifies that the caller has owner-level access to the file before allowing deletion.
     * Owner access is granted if:
     * 1. Caller is the uploader (owner by creation), OR
     * 2. Caller has an OWNER-level AccessShare record for this file
     *
     * @param fileId UUID of the file to delete
     * @param userId User ID from JWT subject to verify caller identity
     * @throws FileNotFoundException if file not found or is deleted
     * @throws FileAccessDeniedException if caller lacks owner-level access
     */
    @Transactional
    public void deleteFile(@NonNull UUID fileId, @NonNull String userId, String email)
            throws FileNotFoundException, FileAccessDeniedException {

        // Retrieve file
        Optional<File> fileOptional = fileRepository.findById(fileId);

        if (fileOptional.isEmpty()) {
            log.warn("File not found for deletion. FileId: {}", fileId);
            throw new FileNotFoundException(fileId);
        }

        File file = fileOptional.get();

        if (file.getIsDeleted()) {
            log.warn("File already deleted. FileId: {}", fileId);
            throw new FileNotFoundException("File already deleted: " + fileId);
        }

        // Check owner access (IDOR prevention)
        if (!hasOwnerAccess(file, userId, email)) {
            log.warn("IDOR attempt blocked: user {} attempted to delete file {} without ownership",
                    userId, fileId);
            throw new FileAccessDeniedException(fileId, null);
        }

        // Perform soft delete
        file.softDelete();
        fileRepository.save(file);

        log.info("File deleted successfully. FileId: {}, DeletedAt: {}, Caller: {}",
                fileId, file.getDeletedAt(), userId);
    }

    /**
     * Check if caller has read access to a file (IDOR prevention).
     *
     * A user has read access if:
     * 1. They are the uploader (owner by creation), OR
     * 2. They have an explicit AccessShare record (OWNER, EDITOR or VIEWER) for this file
     *
     * @param file The file to check access for
     * @param userId The caller's user ID (from JWT subject)
     * @return true if caller has read access, false otherwise
     */
    private boolean hasReadAccess(@NonNull File file, @NonNull String userId, String email) {
        // Check 1: uploader is always allowed
        if (file.getUploadedBy().equals(userId)) {
            return true;
        }

        // Check 2: look for an AccessShare record (resolve by email)
        Optional<UUID> callerUuid = resolveUserUuid(email);
        if (callerUuid.isEmpty()) {
            log.warn("IDOR check: could not resolve internal UUID for userId={}", userId);
            return false;
        }

        Optional<AccessShare> share = accessShareRepository
                .findByResourceIdAndResourceTypeAndGrantedToUserId(
                        file.getId(), AccessShare.ResourceType.FILE, callerUuid.get());

        return share.isPresent(); // any role (OWNER/EDITOR/VIEWER) grants read
    }

    /**
     * Check if caller has owner-level access to a file (IDOR prevention).
     *
     * A user has owner access if:
     * 1. They are the uploader (owner by creation), OR
     * 2. They have an explicit OWNER-level AccessShare record for this file
     *
     * @param file The file to check access for
     * @param userId The caller's user ID (from JWT subject)
     * @return true if caller has owner access, false otherwise
     */
    private boolean hasOwnerAccess(@NonNull File file, @NonNull String userId, String email) {
        // Check 1: uploader is always the owner
        if (file.getUploadedBy().equals(userId)) {
            return true;
        }

        // Check 2: look for an OWNER-level AccessShare record (resolve by email)
        Optional<UUID> callerUuid = resolveUserUuid(email);
        if (callerUuid.isEmpty()) {
            log.warn("IDOR owner check: could not resolve internal UUID for userId={}", userId);
            return false;
        }

        Optional<AccessShare> share = accessShareRepository
                .findByResourceIdAndResourceTypeAndGrantedToUserId(
                        file.getId(), AccessShare.ResourceType.FILE, callerUuid.get());

        return share.isPresent() && share.get().isOwner();
    }

    /**
     * Resolve the internal system UUID for a user by email.
     *
     * Auth0 JWTs include the user's email as the "email" claim.
     * We look up the User entity by email to obtain the internal UUID
     * used in AccessShare records.
     *
     * @param email The user's email
     * @return Optional containing the user's UUID if found, empty otherwise
     */
    private Optional<UUID> resolveUserUuid(String email) {
        if (email == null || email.isBlank()) {
            return Optional.empty();
        }
        return userRepository.findByEmail(email)
                .map(User::getUserId);
    }
}
