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
     * @param callerEmail Email from JWT to resolve caller identity
     * @return File entity if access is granted
     * @throws FileNotFoundException if file not found or is deleted
     * @throws FileAccessDeniedException if caller lacks read access
     */
    @Transactional(readOnly = true)
    @NonNull
    public File downloadFile(@NonNull UUID fileId, @NonNull String callerEmail) throws FileNotFoundException, FileAccessDeniedException {

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
        if (!hasReadAccess(file, callerEmail)) {
            log.warn("IDOR attempt blocked: user {} attempted to access file {} without permission",
                    callerEmail, fileId);
            throw new FileAccessDeniedException(fileId, null);
        }

        log.info("File download verified. FileId: {}, Caller: {}", fileId, callerEmail);

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
     * @param callerEmail Email from JWT to resolve caller identity
     * @throws FileNotFoundException if file not found or is deleted
     * @throws FileAccessDeniedException if caller lacks owner-level access
     */
    @Transactional
    public void deleteFile(@NonNull UUID fileId, @NonNull String callerEmail)
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
        if (!hasOwnerAccess(file, callerEmail)) {
            log.warn("IDOR attempt blocked: user {} attempted to delete file {} without ownership",
                    callerEmail, fileId);
            throw new FileAccessDeniedException(fileId, null);
        }

        // Perform soft delete
        file.softDelete();
        fileRepository.save(file);

        log.info("File deleted successfully. FileId: {}, DeletedAt: {}, Caller: {}",
                fileId, file.getDeletedAt(), callerEmail);
    }

    /**
     * Check if caller has read access to a file (IDOR prevention).
     *
     * A user has read access if:
     * 1. They are the uploader (owner by creation), OR
     * 2. They have an explicit AccessShare record (OWNER, EDITOR or VIEWER) for this file
     *
     * @param file The file to check access for
     * @param callerEmail The caller's email (from JWT)
     * @return true if caller has read access, false otherwise
     */
    private boolean hasReadAccess(@NonNull File file, @NonNull String callerEmail) {
        // Check 1: uploader is always allowed
        if (file.getUploadedBy().equals(callerEmail)) {
            return true;
        }

        // Check 2: look for an AccessShare record
        Optional<UUID> callerUuid = resolveUserUuid(callerEmail);
        if (callerUuid.isEmpty()) {
            log.warn("IDOR check: could not resolve internal UUID for email={}", callerEmail);
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
     * @param callerEmail The caller's email (from JWT)
     * @return true if caller has owner access, false otherwise
     */
    private boolean hasOwnerAccess(@NonNull File file, @NonNull String callerEmail) {
        // Check 1: uploader is always the owner
        if (file.getUploadedBy().equals(callerEmail)) {
            return true;
        }

        // Check 2: look for an OWNER-level AccessShare record
        Optional<UUID> callerUuid = resolveUserUuid(callerEmail);
        if (callerUuid.isEmpty()) {
            log.warn("IDOR owner check: could not resolve internal UUID for email={}", callerEmail);
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
