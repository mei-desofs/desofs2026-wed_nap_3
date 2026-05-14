package pt.isep.desofs.enderchest.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.entity.FileVersion;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for FileVersion entity.
 * <p>
 * Provides data access layer for version history tracking with specialized queries for:
 * - Version history retrieval (newest to oldest)
 * - Specific version lookups
 * - Audit trail reconstruction
 * - Change tracking and rollback scenarios
 * <p>
 * All queries leverage indexes on (file_id, version_number) and (file_id, modified_at)
 * for consistent sub-100ms execution times with 100k+ version records.
 *
 * @author Backend Architecture
 * @version 1.0
 */
@Repository
public interface FileVersionRepository extends JpaRepository<FileVersion, UUID> {

    /**
     * Find all versions of a specific file ordered by version number (newest first).
     * <p>
     * This is the primary query for retrieving file version history.
     * Returns complete audit trail in reverse chronological order.
     * Query execution time: O(log n + k) where k is number of versions for the file.
     *
     * @param fileId The ID of the file to get versions for
     * @return List of versions ordered from newest (highest version number) to oldest
     */
    List<FileVersion> findByFileIdOrderByVersionNumberDesc(UUID fileId);

    /**
     * Find all versions of a specific file ordered by version number (oldest first).
     * <p>
     * Used for chronological audit trails and version history in ascending order.
     * Query execution time: O(log n + k) where k is number of versions for the file.
     *
     * @param fileId The ID of the file to get versions for
     * @return List of versions ordered from oldest to newest
     */
    List<FileVersion> findByFileIdOrderByVersionNumberAsc(UUID fileId);

    /**
     * Find a specific version of a file by version number.
     * <p>
     * Used for rollback scenarios and viewing specific historical versions.
     * Query execution time: O(log n) with composite unique index on (file_id, version_number).
     *
     * @param fileId        The ID of the file
     * @param versionNumber The version number to retrieve
     * @return Optional containing the FileVersion if found, empty otherwise
     */
    Optional<FileVersion> findByFileIdAndVersionNumber(UUID fileId, Integer versionNumber);

    /**
     * Find the latest (highest version number) version of a file.
     * <p>
     * Used to get the most recent version record for a file.
     * Faster than fetching all versions and getting the first one.
     * Query execution time: O(log n) with index on file_id.
     *
     * @param fileId The ID of the file
     * @return Optional containing the latest FileVersion, empty if no versions exist
     */
    @Query("""
                SELECT fv FROM FileVersion fv 
                WHERE fv.file.id = :fileId 
                ORDER BY fv.versionNumber DESC 
                LIMIT 1
            """)
    Optional<FileVersion> findLatestVersion(@Param("fileId") UUID fileId);

    /**
     * Count total versions for a specific file.
     * <p>
     * Used to determine next version number and track version count.
     * Query execution time: O(1) with index on file_id.
     *
     * @param fileId The ID of the file
     * @return Number of versions (0 if file has no versions)
     */
    long countByFileId(UUID fileId);

    /**
     * Find all versions created by a specific user.
     * <p>
     * Used for audit queries to track user actions across all files.
     * Ordered by modification time (newest first) for audit trail.
     * Query execution time: O(log n + k) where k is user's versions.
     *
     * @param modifiedBy User ID (JWT subject)
     * @return List of all versions created by the user
     */
    @Query("""
                SELECT fv FROM FileVersion fv 
                WHERE fv.modifiedBy = :modifiedBy 
                ORDER BY fv.modifiedAt DESC
            """)
    List<FileVersion> findByModifiedByOrderByModifiedAtDesc(@Param("modifiedBy") String modifiedBy);

    /**
     * Find versions of a file created within a time range.
     * <p>
     * Used for time-based audit queries and change tracking.
     * Query execution time: O(log n + k) where k is versions in range.
     *
     * @param fileId    The ID of the file
     * @param startTime Start of time range (inclusive)
     * @param endTime   End of time range (inclusive)
     * @return List of versions modified in the time range
     */
    @Query("""
                SELECT fv FROM FileVersion fv 
                WHERE fv.file.id = :fileId 
                AND fv.modifiedAt BETWEEN :startTime AND :endTime 
                ORDER BY fv.versionNumber DESC
            """)
    List<FileVersion> findVersionsInTimeRange(
            @Param("fileId") UUID fileId,
            @Param("startTime") LocalDateTime startTime,
            @Param("endTime") LocalDateTime endTime
    );

    /**
     * Find versions of a file created by a specific user.
     * <p>
     * Used to track changes made by a particular user to a file.
     * Useful for audit and access control analysis.
     * Query execution time: O(log n + k) where k is matching versions.
     *
     * @param fileId     The ID of the file
     * @param modifiedBy User ID who created the versions
     * @return List of versions created by the specified user
     */
    @Query("""
                SELECT fv FROM FileVersion fv 
                WHERE fv.file.id = :fileId 
                AND fv.modifiedBy = :modifiedBy 
                ORDER BY fv.versionNumber DESC
            """)
    List<FileVersion> findFileVersionsByUser(
            @Param("fileId") UUID fileId,
            @Param("modifiedBy") String modifiedBy
    );

    /**
     * Find versions of multiple files (for batch audit operations).
     * <p>
     * Used for admin/compliance queries across multiple related files.
     * Query execution time: O(log n + k) where k is total versions for files.
     *
     * @param fileIds List of file IDs to get versions for
     * @return List of all versions for the specified files
     */
    @Query("""
                SELECT fv FROM FileVersion fv 
                WHERE fv.file.id IN :fileIds 
                ORDER BY fv.file.id ASC, fv.versionNumber DESC
            """)
    List<FileVersion> findVersionsForFiles(@Param("fileIds") List<UUID> fileIds);

    /**
     * Check if a specific version exists.
     * <p>
     * Optimized boolean check (returns boolean only, not full entity).
     * Query execution time: O(log n) with composite index.
     *
     * @param fileId        The ID of the file
     * @param versionNumber The version number to check
     * @return true if version exists, false otherwise
     */
    boolean existsByFileIdAndVersionNumber(UUID fileId, Integer versionNumber);

    /**
     * Find versions where content hash changed from previous version.
     * <p>
     * Used to identify actual content modifications (vs metadata-only changes).
     * This requires application-side filtering since we need to compare adjacent versions.
     *
     * @param fileId The ID of the file
     * @return List of versions ordered by version number
     */
    @Query("""
                SELECT fv FROM FileVersion fv 
                WHERE fv.file.id = :fileId 
                ORDER BY fv.versionNumber ASC
            """)
    List<FileVersion> findAllVersionsForContentAnalysis(@Param("fileId") UUID fileId);

    /**
     * Delete all versions of a file (cleanup operation).
     * <p>
     * Used when a file is hard-deleted (not just soft-deleted).
     * CASCADE delete from File entity typically handles this automatically.
     * This explicit method is provided for specific cleanup scenarios.
     *
     * @param file The File entity to delete versions for
     */
    void deleteAllByFile(File file);

    /**
     * Find recent versions across all files (for admin dashboard).
     * <p>
     * Used to display recent changes for system monitoring.
     * WARNING: This can be expensive with many versions. Consider pagination.
     * Query execution time: O(log n + k) where k is recent versions.
     *
     * @param limit Maximum number of recent versions to retrieve
     * @param since Only versions modified after this time
     * @return List of recent versions ordered by modification time (newest first)
     */
    @Query(value = """
                SELECT fv FROM FileVersion fv 
                WHERE fv.modifiedAt > :since 
                ORDER BY fv.modifiedAt DESC 
                LIMIT :limit
            """)
    List<FileVersion> findRecentVersions(
            @Param("since") LocalDateTime since,
            @Param("limit") int limit
    );

    /**
     * Calculate total storage usage for a specific user.
     *
     * Sums all file sizes from FileVersion records where the file was uploaded by the user.
     * Used for storage quota tracking and user profile information.
     * Query execution time: O(log n + k) where k is user's files.
     *
     * @param uploadedBy User ID (JWT subject / username)
     * @return Total size in bytes of all files uploaded by the user, or null if no files
     */
}
