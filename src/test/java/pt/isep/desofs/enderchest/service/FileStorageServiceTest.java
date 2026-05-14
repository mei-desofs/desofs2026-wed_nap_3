package pt.isep.desofs.enderchest.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import pt.isep.desofs.enderchest.config.ApplicationProperties;
import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.entity.FileVersion;
import pt.isep.desofs.enderchest.exception.security.FileUploadException;
import pt.isep.desofs.enderchest.exception.security.InvalidFileTypeException;
import pt.isep.desofs.enderchest.exception.security.PathTraversalAttemptException;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.repository.FileVersionRepository;
import pt.isep.desofs.enderchest.repository.FolderRepository;
import pt.isep.desofs.enderchest.service.dto.FileResponse;
import pt.isep.desofs.enderchest.service.dto.UploadResponse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for FileStorageService.
 * 
 * Tests cover:
 * - Upload functionality with SHA-256 hashing
 * - Deduplication detection
 * - Path traversal prevention
 * - MIME type validation
 * - File size validation
 * - Database persistence
 * - Version tracking
 * - Access control
 * - File retrieval with integrity verification
 * - Soft delete operations
 * 
 * @author Backend Architecture
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("FileStorageService Unit Tests")
class FileStorageServiceTest {

    @Mock
    private ApplicationProperties applicationProperties;

    @Mock
    private ApplicationProperties.Storage storageConfig;

    @Mock
    private FileRepository fileRepository;

    @Mock
    private FileVersionRepository fileVersionRepository;

    @Mock
    private FolderRepository folderRepository;

    private FileStorageService fileStorageService;

    @Captor
    private ArgumentCaptor<File> fileCaptor;

    @Captor
    private ArgumentCaptor<FileVersion> versionCaptor;

    private Path testStoragePath;
    private String testUploadedBy = "user@example.com";

    @BeforeEach
    void setUp() throws IOException {
        // Create temporary storage directory
        testStoragePath = Files.createTempDirectory("file-storage-test-");
        
        // Configure mocks (lenient for tests that don't use all stubs)
        lenient().when(applicationProperties.storage()).thenReturn(storageConfig);
        lenient().when(storageConfig.basePath()).thenReturn(testStoragePath.toString());
        lenient().when(storageConfig.allowedMimeTypes()).thenReturn(Set.of(
            "application/pdf",
            "image/jpeg",
            "image/png",
            "text/plain",
            "application/json"
        ));
        lenient().when(storageConfig.maxFileSizeInBytes()).thenReturn(10_485_760L); // 10 MB
        lenient().when(storageConfig.storageQuotaInBytes()).thenReturn(1_073_741_824L); // 1 GB storage quota for tests

        // Recreate service with test path
        fileStorageService = new FileStorageService(applicationProperties, fileRepository, fileVersionRepository, folderRepository);
        fileStorageService.init();
    }

    // ==================== Upload Tests ====================

    @Test
    @DisplayName("Should successfully upload valid file with SHA-256 hash")
    void testUploadValidFile() throws InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        byte[] fileContent = "This is a test file content".getBytes();
        MockMultipartFile uploadFile = new MockMultipartFile(
            "file",
            "test.txt",
            "text/plain",
            fileContent
        );

        File savedFile = new File();
        savedFile.setId(UUID.randomUUID());
        savedFile.setSha256Hash("abc123def456");
        savedFile.setFileSize((long) fileContent.length);
        savedFile.setUploadedAt(LocalDateTime.now());
        savedFile.setMimeType("text/plain");

        when(fileRepository.findBySha256Hash(anyString())).thenReturn(Optional.empty());
        when(fileRepository.save(any(File.class))).thenReturn(savedFile);
        when(fileVersionRepository.save(any(FileVersion.class))).thenReturn(new FileVersion());

        // Act
        UploadResponse response = fileStorageService.uploadFile(uploadFile, testUploadedBy);

        // Assert
        assertNotNull(response);
        assertEquals(savedFile.getId(), response.getFileId());
        assertNotNull(response.getSha256Hash());
        assertEquals(fileContent.length, response.getFileSize());
        assertEquals("text/plain", response.getMimeType());
        
        // Verify persistence
        verify(fileRepository, times(1)).save(any(File.class));
        verify(fileVersionRepository, times(1)).save(any(FileVersion.class));
    }

    
    @Test
    @DisplayName("Should detect path traversal in filename (..) and reject")
    void testPathTraversalDetectionWithDotDot() {
        // Arrange
        MockMultipartFile uploadFile = new MockMultipartFile(
            "file",
            "../../../etc/passwd",
            "text/plain",
            "malicious".getBytes()
        );

        // Act & Assert
        assertThrows(PathTraversalAttemptException.class,
            () -> fileStorageService.uploadFile(uploadFile, testUploadedBy));
        
        // Verify no persistence occurred
        verify(fileRepository, never()).save(any(File.class));
    }

    
    @Test
    @DisplayName("Should detect path traversal in filename (/) and reject")
    void testPathTraversalDetectionWithSlash() {
        // Arrange
        MockMultipartFile uploadFile = new MockMultipartFile(
            "file",
            "subdir/file.txt",
            "text/plain",
            "content".getBytes()
        );

        // Act & Assert
        assertThrows(PathTraversalAttemptException.class,
            () -> fileStorageService.uploadFile(uploadFile, testUploadedBy));
        
        verify(fileRepository, never()).save(any(File.class));
    }

    
    @Test
    @DisplayName("Should reject invalid MIME type (T-06: Web Shell mitigation)")
    void testInvalidMimeTypeRejection() {
        // Arrange
        MockMultipartFile uploadFile = new MockMultipartFile(
            "file",
            "malicious.exe",
            "application/x-msdownload",
            "MZ executable header".getBytes()
        );

        // Act & Assert
        assertThrows(InvalidFileTypeException.class,
            () -> fileStorageService.uploadFile(uploadFile, testUploadedBy));
        
        verify(fileRepository, never()).save(any(File.class));
    }

    
    @Test
    @DisplayName("Should reject files exceeding size limit")
    void testFileSizeValidation() {
        // Arrange
        long maxSize = 100L; // 100 bytes
        when(storageConfig.maxFileSizeInBytes()).thenReturn(maxSize);
        fileStorageService = new FileStorageService(applicationProperties, fileRepository, fileVersionRepository, folderRepository);
        fileStorageService.init();

        MockMultipartFile uploadFile = new MockMultipartFile(
            "file",
            "large.txt",
            "text/plain",
            new byte[(int) (maxSize + 1)]
        );

        // Act & Assert
        assertThrows(FileUploadException.class,
            () -> fileStorageService.uploadFile(uploadFile, testUploadedBy));
        
        verify(fileRepository, never()).save(any(File.class));
    }

    @Test
    @DisplayName("Should reject upload with null filename")
    void testNullFilenameRejection() {
        // Arrange
        MultipartFile uploadFile = mock(MultipartFile.class);
        lenient().when(uploadFile.getOriginalFilename()).thenReturn(null);
        lenient().when(uploadFile.getSize()).thenReturn(100L);

        // Act & Assert
        assertThrows(FileUploadException.class,
            () -> fileStorageService.uploadFile(uploadFile, testUploadedBy));
    }

    @Test
    @DisplayName("Should reject upload with empty filename")
    void testEmptyFilenameRejection() {
        // Arrange
        MockMultipartFile uploadFile = new MockMultipartFile(
            "file",
            "   ",
            "text/plain",
            "content".getBytes()
        );

        // Act & Assert
        assertThrows(FileUploadException.class,
            () -> fileStorageService.uploadFile(uploadFile, testUploadedBy));
    }

    // ==================== Deduplication Tests ====================

    @Test
    @DisplayName("Should detect duplicate files by hash and return existing file")
    void testDuplicateDetection() throws InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        byte[] fileContent = "Duplicate file content".getBytes();
        MockMultipartFile uploadFile = new MockMultipartFile(
            "file",
            "duplicate.txt",
            "text/plain",
            fileContent
        );

        UUID existingFileId = UUID.randomUUID();
        File existingFile = new File();
        existingFile.setId(existingFileId);
        existingFile.setIsDeleted(false);
        existingFile.setSha256Hash("abc123");
        existingFile.setFileSize((long) fileContent.length);
        existingFile.setMimeType("text/plain");
        existingFile.setUploadedAt(LocalDateTime.now());

        when(fileRepository.findBySha256Hash(anyString())).thenReturn(Optional.of(existingFile));

        // Act
        UploadResponse response = fileStorageService.uploadFile(uploadFile, testUploadedBy);

        // Assert
        assertEquals(existingFileId, response.getFileId());
        
        // Verify new persistence was not called
        verify(fileRepository, never()).save(any(File.class));
    }

    @Test
    @DisplayName("Should restore soft-deleted file when duplicate detected")
    void testRestoreDeletedDuplicateFile() throws InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        byte[] fileContent = "Restored file content".getBytes();
        MockMultipartFile uploadFile = new MockMultipartFile(
            "file",
            "restore.txt",
            "text/plain",
            fileContent
        );

        UUID fileId = UUID.randomUUID();
        File deletedFile = new File();
        deletedFile.setId(fileId);
        deletedFile.setIsDeleted(true); // Previously deleted
        deletedFile.setDeletedAt(LocalDateTime.now().minusHours(1));

        when(fileRepository.findBySha256Hash(anyString())).thenReturn(Optional.of(deletedFile));
        when(fileRepository.save(any(File.class))).thenReturn(deletedFile);

        // Act
        UploadResponse response = fileStorageService.uploadFile(uploadFile, testUploadedBy);

        // Assert
        assertEquals(fileId, response.getFileId());
        
        // Verify restoration
        verify(fileRepository, times(1)).save(argThat(file -> !file.getIsDeleted()));
    }

    // ==================== File Retrieval Tests ====================

    @Test
    @DisplayName("Should retrieve file with metadata and verify integrity")
    void testFileRetrieval() throws IOException, FileUploadException {
        // Arrange
        UUID fileId = UUID.randomUUID();
        byte[] fileContent = "Test file content".getBytes();
        
        File file = new File();
        file.setId(fileId);
        file.setOriginalFileName("test.txt");
        file.setMimeType("text/plain");
        file.setFileSize((long) fileContent.length);
        file.setUploadedBy(testUploadedBy);
        file.setIsDeleted(false);
        file.setUploadedAt(LocalDateTime.now());
        
        // Store file on disk
        Path filePath = testStoragePath.resolve(UUID.randomUUID().toString());
        Files.write(filePath, fileContent);
        file.setStorageLocation(filePath.toString());
        
        // Calculate hash
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(fileContent);
            String hash = java.util.HexFormat.of().formatHex(hashBytes);
            file.setSha256Hash(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            fail("SHA-256 algorithm not available");
        }

        when(fileRepository.findByIdAndIsDeletedFalse(fileId)).thenReturn(Optional.of(file));

        // Act
        FileResponse response = fileStorageService.retrieveFile(fileId, testUploadedBy);

        // Assert
        assertNotNull(response);
        assertEquals(fileId, response.getFileId());
        assertEquals("test.txt", response.getOriginalFileName());
        assertArrayEquals(fileContent, response.getFileContent());
        
        // Verify
        verify(fileRepository, times(1)).findByIdAndIsDeletedFalse(fileId);
    }

    @Test
    @DisplayName("Should reject file retrieval for non-existent file")
    void testFileRetrievalNotFound() {
        // Arrange
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findByIdAndIsDeletedFalse(fileId)).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(FileUploadException.class,
            () -> fileStorageService.retrieveFile(fileId, testUploadedBy));
    }

    @Test
    @DisplayName("Should reject file retrieval for unauthorized user (access control)")
    void testFileRetrievalAccessDenied() {
        // Arrange
        UUID fileId = UUID.randomUUID();
        File file = new File();
        file.setId(fileId);
        file.setUploadedBy("owner@example.com"); // Different owner
        file.setIsDeleted(false);

        when(fileRepository.findByIdAndIsDeletedFalse(fileId)).thenReturn(Optional.of(file));

        // Act & Assert
        assertThrows(FileUploadException.class,
            () -> fileStorageService.retrieveFile(fileId, "different@example.com"));
    }

    // ==================== Soft Delete Tests ====================

  
    @Test
    @DisplayName("Should soft-delete file and create version entry")
    void testSoftDeleteFile() throws FileUploadException {
        // Arrange
        UUID fileId = UUID.randomUUID();
        File file = new File();
        file.setId(fileId);
        file.setUploadedBy(testUploadedBy);
        file.setIsDeleted(false);
        file.setSha256Hash("abc123");

        when(fileRepository.findByIdAndIsDeletedFalse(fileId)).thenReturn(Optional.of(file));
        when(fileVersionRepository.countByFileId(fileId)).thenReturn(1L);
        when(fileRepository.save(any(File.class))).thenReturn(file);
        when(fileVersionRepository.save(any(FileVersion.class))).thenReturn(new FileVersion());

        // Act
        fileStorageService.deleteFile(fileId, testUploadedBy);

        // Assert
        verify(fileRepository, times(1)).save(argThat(f -> f.getIsDeleted()));
        verify(fileVersionRepository, times(1)).save(any(FileVersion.class));
    }

    @Test
    @DisplayName("Should reject deletion by non-owner (access control)")
    void testDeleteFileAccessDenied() {
        // Arrange
        UUID fileId = UUID.randomUUID();
        File file = new File();
        file.setId(fileId);
        file.setUploadedBy("owner@example.com");
        file.setIsDeleted(false);

        when(fileRepository.findByIdAndIsDeletedFalse(fileId)).thenReturn(Optional.of(file));

        // Act & Assert
        assertThrows(FileUploadException.class,
            () -> fileStorageService.deleteFile(fileId, "different@example.com"));
    }

    @Test
    @DisplayName("Should reject deletion of already-deleted file")
    void testDeleteAlreadyDeletedFile() {
        // Arrange
        UUID fileId = UUID.randomUUID();
        when(fileRepository.findByIdAndIsDeletedFalse(fileId)).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(FileUploadException.class,
            () -> fileStorageService.deleteFile(fileId, testUploadedBy));
    }

    // ==================== Legacy Method Tests ====================

  
    @Test
    @DisplayName("Should support legacy save() method for backward compatibility")
    void testLegacySaveMethod() throws InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        MockMultipartFile uploadFile = new MockMultipartFile(
            "file",
            "legacy.txt",
            "text/plain",
            "content".getBytes()
        );

        File savedFile = new File();
        savedFile.setId(UUID.randomUUID());
        savedFile.setSha256Hash("abc123");

        when(fileRepository.findBySha256Hash(anyString())).thenReturn(Optional.empty());
        when(fileRepository.save(any(File.class))).thenReturn(savedFile);
        when(fileVersionRepository.save(any(FileVersion.class))).thenReturn(new FileVersion());

        // Act
        fileStorageService.save(uploadFile);

        // Assert - verify no exception thrown
        verify(fileRepository, times(1)).save(any(File.class));
    }
}
