package pt.isep.desofs.enderchest.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;
import pt.isep.desofs.enderchest.entity.File;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for File entity.
 * 
 * Provides data access layer with specialized queries optimized for:
 * - Deduplication detection (SHA-256 hash lookup)
 * - User file queries (access control)
 * - Soft delete filtering (audit compliance)
 * - Performance-critical operations (sub-100ms response time)
 * 
 * All custom queries are designed to leverage database indexes for fast execution.
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@Repository
public interface FileRepository extends JpaRepository<File, UUID> {

    /**
     * Find a file by its SHA-256 hash.
     * 
     * Used for deduplication detection during upload to prevent duplicate storage.
     * Query execution time: O(log n) with index on sha256_hash.
     * 
     * @param sha256Hash The SHA-256 hash to search for
     * @return Optional containing the File if found, empty otherwise
     */
    Optional<File> findBySha256Hash(String sha256Hash);

    /**
     * Find all active (not deleted) files uploaded by a specific user.
     * 
     * Used for user file listing and access control verification.
     * Query leverages composite index (uploaded_by, is_deleted) for performance.
     * Execution time: O(log n + k) where k is number of user's files.
     * 
     * @param uploadedBy User ID (JWT subject) to search for
     * @return List of active files for the user (empty if no files)
     */
    List<File> findByUploadedByAndIsDeletedFalse(String uploadedBy);

    /**
     * Find an active file by ID and verify it hasn't been soft-deleted.
     * 
     * Used for all read operations to ensure only active files are accessed.
     * Automatically filters out soft-deleted files (isDeleted = true).
     * Query execution time: O(log n) with index on primary key.
     * 
     * @param id The file UUID
     * @return Optional containing the File if found and active, empty otherwise
     */
    @NonNull
    Optional<File> findByIdAndIsDeletedFalse(UUID id);

    /**
     * Find all active files uploaded by a user within a time range.
     * 
     * Used for audit queries and time-based file retrieval.
     * Query leverages indexes on (uploaded_by, is_deleted) and (uploaded_at).
     * Execution time: O(log n + k) where k is matching files in time range.
     * 
     * @param uploadedBy User ID to search for
     * @param startTime Start of time range (inclusive)
     * @param endTime End of time range (inclusive)
     * @return List of files matching criteria
     */
    @Query("""
        SELECT f FROM File f 
        WHERE f.uploadedBy = :uploadedBy 
        AND f.isDeleted = false 
        AND f.uploadedAt BETWEEN :startTime AND :endTime 
        ORDER BY f.uploadedAt DESC
    """)
    List<File> findUserFilesInTimeRange(
        @Param("uploadedBy") String uploadedBy,
        @Param("startTime") LocalDateTime startTime,
        @Param("endTime") LocalDateTime endTime
    );

    /**
     * Count active files for a specific user.
     * 
     * Used for quota enforcement and statistics.
     * Query execution time: O(log n) with composite index.
     * 
     * @param uploadedBy User ID to count files for
     * @return Number of active files for the user
     */
    long countByUploadedByAndIsDeletedFalse(String uploadedBy);

    /**
     * Find active files by MIME type (file type).
     * 
     * Used for filtering files by type (e.g., images, documents).
     * Supports media type queries and file type statistics.
     * 
     * @param mimeType The MIME type to search for (e.g., "image/jpeg")
     * @return List of active files with matching MIME type
     */
    List<File> findByMimeTypeAndIsDeletedFalse(String mimeType);

    /**
     * Find files uploaded within a specific time range (admin query).
     * 
     * Used for administrative audit operations and time-based reports.
     * Query execution time: O(log n + k) where k is files in time range.
     * 
     * @param startTime Start of time range (inclusive)
     * @param endTime End of time range (inclusive)
     * @return List of files uploaded in the specified range
     */
    @Query("""
        SELECT f FROM File f 
        WHERE f.uploadedAt BETWEEN :startTime AND :endTime 
        AND f.isDeleted = false 
        ORDER BY f.uploadedAt DESC
    """)
    List<File> findFilesUploadedInRange(
        @Param("startTime") LocalDateTime startTime,
        @Param("endTime") LocalDateTime endTime
    );

    /**
     * Check if a file with given SHA-256 hash exists (before upload).
     * 
     * Optimized for deduplication check - returns boolean only, no full entity fetch.
     * Query execution time: O(log n) with unique index on sha256_hash.
     * 
     * @param sha256Hash The hash to check
     * @return true if file with this hash exists, false otherwise
     */
    boolean existsBySha256Hash(String sha256Hash);

    /**
     * Find all active files (admin query).
     * 
     * WARNING: Use with caution in production! 
     * Consider pagination for large datasets (100k+ files).
     * This should typically not be called without filtering.
     * 
     * @return List of all active files in the system
     */
    @Query("SELECT f FROM File f WHERE f.isDeleted = false ORDER BY f.uploadedAt DESC")
    List<File> findAllActive();

    /**
     * Find files that haven't been accessed recently (cleanup/archive candidates).
     * 
     * Used for identifying old files for archival or deletion policies.
     * Query execution time: O(log n + k) where k is old files.
     * 
     * @param beforeTime Cutoff timestamp
     * @return List of inactive files not touched since beforeTime
     */
    @Query("""
        SELECT f FROM File f 
        WHERE f.uploadedAt < :beforeTime 
        AND f.isDeleted = false 
        ORDER BY f.uploadedAt ASC
    """)
    List<File> findOldFiles(@Param("beforeTime") LocalDateTime beforeTime);

    /**
     * Find all active files in a specific folder for a user.
     * 
     * Used for folder-based file listing and access control verification.
     * Query leverages composite index (folder_id, is_deleted) for performance.
     * Execution time: O(log n + k) where k is number of files in folder.
     * 
     * @param folderId The folder UUID to search within
     * @return List of active files in the specified folder (empty if no files)
     */
    @NonNull
    List<File> findByFolderIdAndIsDeletedFalse(UUID folderId);

    /**
     * Find all active files uploaded by a specific user using UUID ownerId.
     * 
     * Alternative method using UUID ownerId for consistency with newer API.
     * Used for user file listing and quota calculations.
     * Query leverages composite index (uploaded_by, is_deleted) for performance.
     * 
     * @param ownerId User ID (UUID) to search for
     * @return List of active files for the user (empty if no files)
     */
    @NonNull
    @Query("""
        SELECT f FROM File f 
        WHERE f.uploadedBy = CAST(:ownerId AS string)
        AND f.isDeleted = false 
        ORDER BY f.uploadedAt DESC
    """)
    List<File> findByOwnerIdAndIsDeletedFalse(@Param("ownerId") UUID ownerId);

    /**
     * Calculate total storage usage for a specific user.
     * 
     * Sums the size of all active files for a user.
     * Used for quota enforcement and storage statistics.
     * JPQL query performs aggregation at database level for efficiency.
     * Query execution time: O(n) where n is number of user's files.
     * 
     * @param ownerId User ID (UUID) to calculate storage for
     * @return Total storage usage in bytes (0 if user has no files)
     */
    @Query("""
        SELECT COALESCE(SUM(f.fileSize), 0L) FROM File f 
        WHERE f.uploadedBy = CAST(:ownerId AS string)
        AND f.isDeleted = false
    """)
    @NonNull
    Long calculateUserStorageUsage(@Param("ownerId") UUID ownerId);

    /**
     * Calculate total storage usage for a user using String ownerId.
     * 
     * Sums the size of all active files for a user.
     * Used for quota enforcement and storage statistics.
     * 
     * @param ownerId User ID (String) to calculate storage for
     * @return Total storage usage in bytes (0 if user has no files)
     */
    @Query("""
        SELECT COALESCE(SUM(f.fileSize), 0L) FROM File f 
        WHERE f.uploadedBy = :ownerId
        AND f.isDeleted = false
    """)
    Long calculateUserStorageUsageByString(@Param("ownerId") String ownerId);

    /**
     * Calculate total storage usage by summing File sizes for a user.
     *
     * This query aggregates file sizes for all files owned by a user.
     * Used for accurate storage quota enforcement and analytics.
     *
     * @param username The username (uploadedBy field) to calculate storage for
     * @return Total storage used in bytes (sum of all file sizes for active files)
     */
    @Query("""
        SELECT COALESCE(SUM(f.fileSize), 0L) FROM File f 
        WHERE f.uploadedBy = :username AND f.isDeleted = false
    """)
    long sumFileSizeByUploadedBy(@Param("username") String username);
}
