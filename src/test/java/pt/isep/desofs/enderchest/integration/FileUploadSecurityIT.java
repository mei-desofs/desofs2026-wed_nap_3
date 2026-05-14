package pt.isep.desofs.enderchest.integration;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.multipart.MultipartFile;

import pt.isep.desofs.enderchest.entity.File;
import pt.isep.desofs.enderchest.exception.security.InvalidFileTypeException;
import pt.isep.desofs.enderchest.exception.security.PathTraversalAttemptException;
import pt.isep.desofs.enderchest.exception.security.FileUploadException;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.service.FileStorageService;
import pt.isep.desofs.enderchest.service.dto.UploadResponse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive Integration Tests for EnderChest File Storage Security Features.
 * 
 * Tests Cover:
 * - ST-01: Path Traversal Prevention
 * - ST-03: File Type Validation
 * - SHA-256 Hash Calculation and Persistence
 * - Database Integration
 * - Soft Delete and Deduplication
 * 
 * Security Verification Scope:
 * ✅ Path traversal blocked for ../ patterns
 * ✅ Path traversal blocked for / patterns
 * ✅ Path traversal blocked for absolute paths
 * ✅ Executable files (.exe, .bat, .sh) blocked
 * ✅ Valid files (PDF, images) allowed
 * ✅ Valid files have SHA-256 hash persisted
 * ✅ Soft delete works
 * ✅ Deduplication detection works
 * 
 * Performance Targets:
 * - Each test completes in <1 second
 * - Database operations <100ms
 * - Total suite execution <30 seconds
 * 
 * @author Security Testing Team
 * @version 1.0
 */
@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "classpath:application-test.properties")
@DisplayName("FileUploadSecurityIT: Comprehensive Security Integration Tests")
class FileUploadSecurityIT {

    @Autowired
    private FileStorageService fileStorageService;

    @Autowired
    private FileRepository fileRepository;

    private String testUploadedBy = "test-user@example.com";

    /**
     * Setup test environment before each test.
     * Test storage directory is configured in application-test.properties.
     */
    @BeforeEach
    void setUp() throws IOException {
        // Storage directory is already set up by Spring configuration
        // Just verify it exists
        Path storageDir = Paths.get("/tmp/enderchest_test_uploads");
        if (!Files.exists(storageDir)) {
            Files.createDirectories(storageDir);
        }
        log.info("Test setup complete. Storage directory: {}", storageDir);
    }

    /**
     * Cleanup after each test.
     * Removes all test files from storage directory.
     */
    @AfterEach
    void tearDown() throws IOException {
        Path storageDir = Paths.get("/tmp/enderchest_test_uploads");
        if (storageDir != null && Files.exists(storageDir)) {
            Files.walk(storageDir)
                    .filter(Files::isRegularFile)
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            log.warn("Could not delete test file: {}", path, e);
                        }
                    });
        }
        log.info("Test cleanup complete");
    }

    // ============================================================
    // ST-01: PATH TRAVERSAL ATTACK PREVENTION TESTS
    // ============================================================

    @Test
    @DisplayName("ST-01-A: Upload with path traversal (../) should throw PathTraversalAttemptException")
    void testUploadWithPathTraversal_ContainingDoubleDots_ThrowsException() {
        // Arrange
        String maliciousFilename = "../../etc/passwd.txt";
        byte[] fileContent = "malicious content".getBytes();
        MultipartFile file = createMockMultipartFile(maliciousFilename, fileContent, "text/plain");

        // Act & Assert
        PathTraversalAttemptException exception = assertThrows(
                PathTraversalAttemptException.class,
                () -> fileStorageService.uploadFile(file, testUploadedBy),
                "Should throw PathTraversalAttemptException for ../ pattern"
        );

        // Verify exception message
        String errorMessage = extractExceptionMessage(exception);
        assertAll(
                () -> assertNotNull(errorMessage, "Exception message should not be null"),
                () -> assertTrue(
                        errorMessage.toLowerCase().contains("path traversal"),
                        "Exception message should contain 'Path Traversal'"
                ),
                () -> assertTrue(
                        errorMessage.toLowerCase().contains("blocked"),
                        "Exception message should indicate the attempt was blocked"
                )
        );

        log.info("✅ ST-01-A: Path traversal with ../ successfully blocked");
    }

    @Test
    @DisplayName("ST-01-B: Upload with path traversal (/) should throw PathTraversalAttemptException")
    void testUploadWithPathTraversal_ContainingSlash_ThrowsException() {
        // Arrange
        String maliciousFilename = "/etc/passwd";
        byte[] fileContent = "sensitive data".getBytes();
        MultipartFile file = createMockMultipartFile(maliciousFilename, fileContent, "text/plain");

        // Act & Assert
        PathTraversalAttemptException exception = assertThrows(
                PathTraversalAttemptException.class,
                () -> fileStorageService.uploadFile(file, testUploadedBy),
                "Should throw PathTraversalAttemptException for leading / path"
        );

        String errorMessage = extractExceptionMessage(exception);
        assertTrue(
                errorMessage.toLowerCase().contains("path traversal"),
                "Exception message should indicate path traversal detection"
        );

        log.info("✅ ST-01-B: Path traversal with / successfully blocked");
    }

    @Test
    @DisplayName("ST-01-C: Upload with Windows absolute path should throw PathTraversalAttemptException")
    void testUploadWithPathTraversal_ContainingAbsolutePath_ThrowsException() {
        // Arrange
        String maliciousFilename = "C:\\Windows\\System32\\file.txt";
        byte[] fileContent = "windows exploit".getBytes();
        MultipartFile file = createMockMultipartFile(maliciousFilename, fileContent, "text/plain");

        // Act & Assert
        PathTraversalAttemptException exception = assertThrows(
                PathTraversalAttemptException.class,
                () -> fileStorageService.uploadFile(file, testUploadedBy),
                "Should throw PathTraversalAttemptException for Windows absolute path"
        );

        assertNotNull(extractExceptionMessage(exception));

        log.info("✅ ST-01-C: Windows absolute path successfully blocked");
    }

    @Test
    @DisplayName("ST-01-D: Upload with backslash traversal should throw PathTraversalAttemptException")
    void testUploadWithPathTraversal_BackslashTraversal_ThrowsException() {
        // Arrange
        String maliciousFilename = "..\\..\\windows\\temp.txt";
        byte[] fileContent = "windows traversal".getBytes();
        MultipartFile file = createMockMultipartFile(maliciousFilename, fileContent, "text/plain");

        // Act & Assert
        PathTraversalAttemptException exception = assertThrows(
                PathTraversalAttemptException.class,
                () -> fileStorageService.uploadFile(file, testUploadedBy),
                "Should throw PathTraversalAttemptException for backslash traversal"
        );

        assertNotNull(extractExceptionMessage(exception));

        log.info("✅ ST-01-D: Backslash traversal successfully blocked");
    }

    @Test
    @DisplayName("ST-01-E: Upload with valid filename should succeed")
    @SuppressWarnings("null")
    void testUploadWithValidFilename_Succeeds() throws FileUploadException, InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        String validFilename = "document.pdf";
        byte[] pdfContent = createPdfContent();
        MultipartFile file = createMockMultipartFile(validFilename, pdfContent, "application/pdf");

        // Act
        UploadResponse response = fileStorageService.uploadFile(file, testUploadedBy);

        // Assert
        assertAll(
                () -> assertNotNull(response, "Response should not be null"),
                () -> assertNotNull(response.getFileId(), "File ID should not be null"),
                () -> assertNotNull(response.getSha256Hash(), "SHA-256 hash should not be null"),
                () -> assertTrue(
                        response.getSha256Hash().matches("[a-fA-F0-9]{64}"),
                        "SHA-256 hash should be 64 hexadecimal characters"
                ),
                () -> assertEquals(pdfContent.length, response.getFileSize(), "File size should match"),
                () -> assertEquals("application/pdf", response.getMimeType(), "MIME type should match")
        );

        // Verify file is persisted in database
        Optional<File> persistedFile = fileRepository.findById(response.getFileId());
        assertTrue(persistedFile.isPresent(), "File should be persisted in database");
        assertEquals(response.getSha256Hash(), persistedFile.get().getSha256Hash(), "Hash should match");

        log.info("✅ ST-01-E: Valid PDF file upload succeeded with hash: {}", response.getSha256Hash());
    }

    // ============================================================
    // ST-03: FILE TYPE VALIDATION TESTS
    // ============================================================

    @Test
    @DisplayName("ST-03-A: Upload executable file (.exe) should throw InvalidFileTypeException")
    void testUploadExecutableFile_WithExeExtension_ThrowsException() {
        // Arrange
        String executableFilename = "malware.exe";
        byte[] exeContent = createExecutableContent(); // MZ... magic bytes for PE executables
        MultipartFile file = createMockMultipartFile(executableFilename, exeContent, "application/x-msdownload");

        // Act & Assert
        InvalidFileTypeException exception = assertThrows(
                InvalidFileTypeException.class,
                () -> fileStorageService.uploadFile(file, testUploadedBy),
                "Should throw InvalidFileTypeException for .exe file"
        );

        String errorMessage = extractExceptionMessage(exception);
        assertAll(
                () -> assertNotNull(errorMessage, "Exception message should not be null"),
                () -> assertTrue(
                        errorMessage.toLowerCase().contains("not allowed"),
                        "Exception message should indicate file type is not allowed"
                )
        );

        log.info("✅ ST-03-A: Executable .exe file successfully blocked");
    }

    @Test
    @DisplayName("ST-03-B: Upload batch script file (.bat) should throw InvalidFileTypeException")
    void testUploadScriptFile_WithBatExtension_ThrowsException() {
        // Arrange
        String scriptFilename = "script.bat";
        byte[] batContent = "@echo off\necho Malicious batch script\n".getBytes();
        MultipartFile file = createMockMultipartFile(scriptFilename, batContent, "application/x-bat");

        // Act & Assert
        InvalidFileTypeException exception = assertThrows(
                InvalidFileTypeException.class,
                () -> fileStorageService.uploadFile(file, testUploadedBy),
                "Should throw InvalidFileTypeException for .bat file"
        );

        assertNotNull(extractExceptionMessage(exception));

        log.info("✅ ST-03-B: Batch script .bat file successfully blocked");
    }

    @Test
    @DisplayName("ST-03-C: Upload shell script file (.sh) should throw InvalidFileTypeException")
    void testUploadScriptFile_WithShExtension_ThrowsException() {
        // Arrange
        String scriptFilename = "exploit.sh";
        byte[] shContent = "#!/bin/bash\necho 'malicious'\nrm -rf /\n".getBytes();
        MultipartFile file = createMockMultipartFile(scriptFilename, shContent, "application/x-sh");

        // Act & Assert
        InvalidFileTypeException exception = assertThrows(
                InvalidFileTypeException.class,
                () -> fileStorageService.uploadFile(file, testUploadedBy),
                "Should throw InvalidFileTypeException for .sh file"
        );

        assertNotNull(extractExceptionMessage(exception));

        log.info("✅ ST-03-C: Shell script .sh file successfully blocked");
    }

    @Test
    @DisplayName("ST-03-D: Upload JAR file (.jar) should throw InvalidFileTypeException")
    void testUploadJarFile_WithJarExtension_ThrowsException() {
        // Arrange
        String jarFilename = "app.jar";
        byte[] jarContent = createZipContent(); // ZIP magic bytes (PK...) for JAR files
        MultipartFile file = createMockMultipartFile(jarFilename, jarContent, "application/java-archive");

        // Act & Assert
        InvalidFileTypeException exception = assertThrows(
                InvalidFileTypeException.class,
                () -> fileStorageService.uploadFile(file, testUploadedBy),
                "Should throw InvalidFileTypeException for .jar file"
        );

        assertNotNull(extractExceptionMessage(exception));

        log.info("✅ ST-03-D: Java archive .jar file successfully blocked");
    }

    @Test
    @DisplayName("ST-03-E: Upload valid PDF file should succeed")
    void testUploadValidPdf_Succeeds() throws FileUploadException, InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        String pdfFilename = "document.pdf";
        byte[] pdfContent = createPdfContent();
        MultipartFile file = createMockMultipartFile(pdfFilename, pdfContent, "application/pdf");

        // Act
        UploadResponse response = fileStorageService.uploadFile(file, testUploadedBy);

        // Assert
        assertNotNull(response, "Response should not be null");
        assertNotNull(response.getSha256Hash(), "SHA-256 hash should be calculated");

        // Verify persistence
        assertNotNull(response.getFileId(), "File ID should not be null");
        Optional<File> persistedFile = fileRepository.findById(response.getFileId());
        assertTrue(persistedFile.isPresent(), "File should be persisted");
        assertTrue(
                persistedFile.get().getSha256Hash().matches("[a-fA-F0-9]{64}"),
                "SHA-256 hash should be valid hex format"
        );

        log.info("✅ ST-03-E: Valid PDF file successfully uploaded with hash: {}", response.getSha256Hash());
    }

    @Test
    @DisplayName("ST-03-F: Upload valid JPEG image should succeed")
    @SuppressWarnings("null")
    void testUploadValidImage_WithJpegExtension_Succeeds() throws FileUploadException, InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        String imageFilename = "photo.jpg";
        byte[] jpegContent = createJpegContent();
        MultipartFile file = createMockMultipartFile(imageFilename, jpegContent, "image/jpeg");

        // Act
        UploadResponse response = fileStorageService.uploadFile(file, testUploadedBy);

        // Assert
        assertNotNull(response, "Response should not be null");
        assertEquals("image/jpeg", response.getMimeType(), "MIME type should be image/jpeg");

        // Verify persistence
        Optional<File> persistedFile = fileRepository.findById(response.getFileId());
        assertTrue(persistedFile.isPresent(), "File should be persisted");
        assertEquals(jpegContent.length, persistedFile.get().getFileSize(), "Size should match");

        log.info("✅ ST-03-F: Valid JPEG image successfully uploaded");
    }

    // ============================================================
    // DEDUPLICATION TESTS
    // ============================================================

    @Test
    @DisplayName("ST-04-A: Upload duplicate file should return existing file ID")
    void testUploadDuplicateFile_ShouldDetectDeduplication() throws FileUploadException, InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        String filename1 = "document1.pdf";
        String filename2 = "document2.pdf";
        byte[] pdfContent = createPdfContent();

        MultipartFile file1 = createMockMultipartFile(filename1, pdfContent, "application/pdf");
        MultipartFile file2 = createMockMultipartFile(filename2, pdfContent, "application/pdf");

        // Act
        UploadResponse response1 = fileStorageService.uploadFile(file1, testUploadedBy);
        UploadResponse response2 = fileStorageService.uploadFile(file2, testUploadedBy);

        // Assert
        assertEquals(
                response1.getFileId(),
                response2.getFileId(),
                "Duplicate files should have same ID (deduplication)"
        );
        assertEquals(
                response1.getSha256Hash(),
                response2.getSha256Hash(),
                "Duplicate files should have same hash"
        );

        log.info("✅ ST-04-A: Deduplication successfully detected duplicate file");
    }

    // ============================================================
    // SOFT DELETE TESTS
    // ============================================================

    @Test
    @DisplayName("ST-05-A: Soft delete file should mark as deleted")
    @SuppressWarnings("null")
    void testSoftDeleteFile_ShouldMarkAsDeleted() throws FileUploadException, InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        String filename = "document.pdf";
        byte[] pdfContent = createPdfContent();
        MultipartFile file = createMockMultipartFile(filename, pdfContent, "application/pdf");

        UploadResponse uploadResponse = fileStorageService.uploadFile(file, testUploadedBy);
        UUID fileId = uploadResponse.getFileId();

        // Act
        fileStorageService.deleteFile(fileId, testUploadedBy);

        // Assert
        Optional<File> deletedFile = fileRepository.findById(fileId);
        assertTrue(deletedFile.isPresent(), "File entity should still exist (soft delete)");
        assertTrue(deletedFile.get().getIsDeleted(), "File should be marked as deleted");
        assertNotNull(deletedFile.get().getDeletedAt(), "Deletion timestamp should be recorded");

        log.info("✅ ST-05-A: Soft delete successfully marked file as deleted");
    }

    @Test
    @DisplayName("ST-05-B: Retrieve soft-deleted file should fail")
    void testRetrieveSoftDeletedFile_ShouldFail() throws FileUploadException, InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        String filename = "document.pdf";
        byte[] pdfContent = createPdfContent();
        MultipartFile file = createMockMultipartFile(filename, pdfContent, "application/pdf");

        UploadResponse uploadResponse = fileStorageService.uploadFile(file, testUploadedBy);
        UUID fileId = uploadResponse.getFileId();
        fileStorageService.deleteFile(fileId, testUploadedBy);

        // Act & Assert
        FileUploadException exception = assertThrows(
                FileUploadException.class,
                () -> fileStorageService.retrieveFile(fileId, testUploadedBy),
                "Should not be able to retrieve soft-deleted file"
        );

        assertTrue(
                extractExceptionMessage(exception).toLowerCase().contains("deleted"),
                "Exception message should indicate file is deleted"
        );

        log.info("✅ ST-05-B: Soft-deleted file successfully blocked from retrieval");
    }

    // ============================================================
    // SHA-256 HASH INTEGRITY TESTS
    // ============================================================

    @Test
    @DisplayName("ST-06-A: Uploaded file should have valid SHA-256 hash")
    void testUploadedFile_ShouldHaveValidSha256Hash() throws FileUploadException, InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        String filename = "document.pdf";
        byte[] pdfContent = createPdfContent();
        MultipartFile file = createMockMultipartFile(filename, pdfContent, "application/pdf");

        // Act
        UploadResponse response = fileStorageService.uploadFile(file, testUploadedBy);

        // Assert
        String hash = response.getSha256Hash();
        assertAll(
                () -> assertNotNull(hash, "Hash should not be null"),
                () -> assertEquals(64, hash.length(), "SHA-256 hash should be 64 hex characters"),
                () -> assertTrue(
                        hash.matches("[a-fA-F0-9]{64}"),
                        "Hash should be valid hexadecimal"
                )
        );

        log.info("✅ ST-06-A: SHA-256 hash is valid: {}", hash);
    }

    @Test
    @DisplayName("ST-06-B: File hash persistence in database")
    @SuppressWarnings("null")
    void testFileRetrieval_ShouldVerifyHashPersistence() throws FileUploadException, InvalidFileTypeException, PathTraversalAttemptException {
        // Arrange
        // Use unique timestamp to avoid deduplication
        String filename = "document_persistence_" + System.nanoTime() + ".txt";
        String contentString = "Unique content for hash verification: " + System.nanoTime();
        byte[] fileContent = contentString.getBytes();
        MultipartFile file = createMockMultipartFile(filename, fileContent, "text/plain");

        UploadResponse uploadResponse = fileStorageService.uploadFile(file, testUploadedBy);
        UUID fileId = uploadResponse.getFileId();

        // Act & Assert: Verify hash is persisted correctly in database
        Optional<File> fileEntity = fileRepository.findById(fileId);
        
        assertTrue(fileEntity.isPresent(), "File should be persisted in database");
        assertEquals(uploadResponse.getSha256Hash(), fileEntity.get().getSha256Hash(), 
                "Hash should match between response and database");
        assertEquals(fileContent.length, fileEntity.get().getFileSize(), 
                "File size should match in database");
        assertEquals("text/plain", fileEntity.get().getMimeType(), 
                "MIME type should be persisted");
        assertFalse(fileEntity.get().getIsDeleted(), "File should not be marked as deleted");
        assertNotNull(fileEntity.get().getUploadedAt(), "Upload timestamp should be recorded");

        log.info("✅ ST-06-B: File hash persistence verified in database");
    }

    // ============================================================
    // HELPER METHODS
    // ============================================================

    /**
     * Create a MockMultipartFile with specified content and MIME type.
     * 
     * @param filename Original filename
     * @param content File content bytes
     * @param mimeType MIME type/content type
     * @return MockMultipartFile instance
     */
    private MockMultipartFile createMockMultipartFile(String filename, byte[] content, String mimeType) {
        return new MockMultipartFile(
                "file",
                filename,
                mimeType,
                content
        );
    }

    /**
     * Extract exception message safely from exception.
     * 
     * @param exception Exception to extract message from
     * @return Exception message or empty string if null
     */
    private String extractExceptionMessage(Exception exception) {
        String message = exception.getMessage();
        return message != null ? message : "";
    }

    /**
     * Create valid PDF file content with magic bytes.
     * PDF files start with %PDF magic bytes.
     * 
     * @return Byte array containing minimal valid PDF
     */
    private byte[] createPdfContent() {
        String pdfContent = "%PDF-1.4\n" +
                "1 0 obj\n" +
                "<< /Type /Catalog /Pages 2 0 R >>\n" +
                "endobj\n" +
                "2 0 obj\n" +
                "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n" +
                "endobj\n" +
                "3 0 obj\n" +
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\n" +
                "endobj\n" +
                "4 0 obj\n" +
                "<< /Length 44 >>\n" +
                "stream\n" +
                "BT\n" +
                "/F1 12 Tf\n" +
                "100 700 Td\n" +
                "(Hello World) Tj\n" +
                "ET\n" +
                "endstream\n" +
                "endobj\n" +
                "xref\n" +
                "0 5\n" +
                "0000000000 65535 f \n" +
                "0000000009 00000 n \n" +
                "0000000074 00000 n \n" +
                "0000000120 00000 n \n" +
                "0000000203 00000 n \n" +
                "trailer\n" +
                "<< /Size 5 /Root 1 0 R >>\n" +
                "startxref\n" +
                "305\n" +
                "%%EOF";
        return pdfContent.getBytes();
    }

    /**
     * Create valid JPEG image content with magic bytes.
     * JPEG files start with FFD8FF magic bytes (JPEG SOI marker).
     * 
     * @return Byte array containing minimal valid JPEG
     */
    private byte[] createJpegContent() {
        byte[] jpegHeader = new byte[]{
                (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, // JPEG SOI marker
                (byte) 0xE0, 0x00, 0x10,               // APP0 segment
                0x4A, 0x46, 0x49, 0x46, 0x00,          // JFIF identifier
                0x01, 0x01,                             // Version
                0x00,                                   // Aspect ratio units
                0x00, 0x01,                             // X density
                0x00, 0x01,                             // Y density
                0x00, 0x00                              // Thumbnail dimensions
        };
        byte[] jpegFooter = new byte[]{
                (byte) 0xFF, (byte) 0xD9                // JPEG EOI marker
        };
        byte[] result = new byte[jpegHeader.length + jpegFooter.length];
        System.arraycopy(jpegHeader, 0, result, 0, jpegHeader.length);
        System.arraycopy(jpegFooter, 0, result, jpegHeader.length, jpegFooter.length);
        return result;
    }

    /**
     * Create executable file content with PE header magic bytes.
     * Windows PE executables start with "MZ" magic bytes (0x4D5A).
     * 
     * @return Byte array containing PE header
     */
    private byte[] createExecutableContent() {
        byte[] exeHeader = new byte[]{
                (byte) 0x4D, (byte) 0x5A,                  // "MZ" magic bytes (PE executable)
                (byte) 0x90, (byte) 0x00, (byte) 0x03, (byte) 0x00, (byte) 0x00, (byte) 0x00,    // DOS header
                (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00,                // File parameters
                (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00,  // More header data
        };
        byte[] padding = new byte[64];
        byte[] result = new byte[exeHeader.length + padding.length];
        System.arraycopy(exeHeader, 0, result, 0, exeHeader.length);
        System.arraycopy(padding, 0, result, exeHeader.length, padding.length);
        return result;
    }

    /**
     * Create ZIP/JAR file content with ZIP archive magic bytes.
     * ZIP files start with "PK" magic bytes (0x504B).
     * JAR files are ZIP archives with Java class files.
     * 
     * @return Byte array containing ZIP header
     */
    private byte[] createZipContent() {
        byte[] zipHeader = new byte[]{
                (byte) 0x50, (byte) 0x4B,                  // "PK" magic bytes (ZIP archive)
                (byte) 0x03, (byte) 0x04,                 // ZIP version to extract
                (byte) 0x14, (byte) 0x00,                 // General purpose bit flag
                (byte) 0x00, (byte) 0x00,                 // Compression method
                (byte) 0x00, (byte) 0x00,                 // File modification time
                (byte) 0x00, (byte) 0x00,                 // File modification date
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,                 // CRC-32
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,                 // Compressed size
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,                 // Uncompressed size
                (byte) 0x00, (byte) 0x00,                 // Filename length
                (byte) 0x00, (byte) 0x00                  // Extra field length
        };
        byte[] padding = new byte[32];
        byte[] result = new byte[zipHeader.length + padding.length];
        System.arraycopy(zipHeader, 0, result, 0, zipHeader.length);
        System.arraycopy(padding, 0, result, zipHeader.length, padding.length);
        return result;
    }
}
