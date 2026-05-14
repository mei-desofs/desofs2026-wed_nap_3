# Bruno API Test Collection - EnderChest

Bruno is a lightweight API client (alternative to Postman). This folder contains all test requests for the EnderChest file storage API.

## Installation

1. Download Bruno from: https://www.usebruno.com/
2. Open Bruno
3. File → Open Collection → Select this `collection` folder

## Setup

1. Start the application:
   ```bash
   docker-compose up --build
   ```

2. In Bruno, configure environment variables:
   - `base_url`: http://localhost:8080
   - `bearer_token`: test-token

## Test Files

Create test files for upload testing:

```bash
mkdir -p bruno/collection/test-files

# Create legitimate files
echo "%PDF-1.4" > bruno/collection/test-files/document.pdf
printf '\xFF\xD8\xFF' > bruno/collection/test-files/photo.jpg

# Create malicious files (for testing prevention)
printf 'MZ' > bruno/collection/test-files/malware.exe
printf 'PK' > bruno/collection/test-files/app.jar
echo "#!/bin/bash" > bruno/collection/test-files/exploit.sh
echo "@echo off" > bruno/collection/test-files/script.bat
```

## Running Tests

### Option 1: Run All Requests
- Select all requests in Bruno
- Click "Run Collection"

### Option 2: Run Individual Tests
1. Click on a request (e.g., "01_Upload_Valid_PDF")
2. Click "Send"
3. View response and test results

## Test Requests

### Valid Uploads (Should Succeed)
- 01_Upload_Valid_PDF.yaml → 200 OK, returns fileId and SHA-256 hash
- 02_Upload_Valid_Image.yaml → 200 OK, returns JPEG MIME type

### Path Traversal Prevention Tests (Should Fail)
- 03_Path_Traversal_DoubleDots.yaml → 400 Bad Request
- 04_Path_Traversal_AbsolutePath.yaml → 400 Bad Request

### File Type Validation Tests (Should Fail)
- 05_FileType_Block_EXE.yaml → 400 Bad Request
- 06_FileType_Block_BAT.yaml → 400 Bad Request
- 07_FileType_Block_SH.yaml → 400 Bad Request
- 08_FileType_Block_JAR.yaml → 400 Bad Request

### Security Tests
- 09_Deduplication_Same_File.yaml → 200 OK (same fileId on second upload)
- 10_Hash_Verification_SHA256.yaml → SHA-256 must be 64 hex characters

## Expected Results

All valid uploads should return 200 with:
```json
{
  "fileId": "uuid",
  "sha256Hash": "64-character hex string",
  "fileSize": 1024,
  "mimeType": "application/pdf",
  "uploadedAt": "2026-05-12T..."
}
```

All malicious uploads should return 400 with:
```json
{
  "error": "INVALID_FILE_TYPE" or "PATH_TRAVERSAL_DETECTED"
}
```

## Running via Command Line

Bruno can also be run from terminal:

```bash
bruno run collection --env production
```

## File Structure

```
bruno/
└── collection/
    ├── bruno.json                          (Collection config)
    ├── 01_Upload_Valid_PDF.yaml
    ├── 02_Upload_Valid_Image.yaml
    ├── 03_Path_Traversal_DoubleDots.yaml
    ├── 04_Path_Traversal_AbsolutePath.yaml
    ├── 05_FileType_Block_EXE.yaml
    ├── 06_FileType_Block_BAT.yaml
    ├── 07_FileType_Block_SH.yaml
    ├── 08_FileType_Block_JAR.yaml
    ├── 09_Deduplication_Same_File.yaml
    ├── 10_Hash_Verification_SHA256.yaml
    ├── README.md                           (This file)
    └── test-files/                         (Create these locally)
        ├── document.pdf
        ├── photo.jpg
        ├── malware.exe
        ├── app.jar
        ├── exploit.sh
        └── script.bat
```

## Troubleshooting

**Collection won't open?**
- Ensure bruno.json is in the root of the collection folder
- Check that all .yaml files are in the same folder

**Tests won't run?**
- Verify application is running: docker-compose up --build
- Check base_url is correct: http://localhost:8080
- Create test files in test-files/ subdirectory

**File upload fails?**
- Ensure test files exist in test-files/ folder
- Check file paths in .yaml files match actual locations
- Verify file contents match expected magic bytes

## Security Test Coverage

These tests verify:
- CWE-22: Path Traversal Prevention ✓
- CWE-434: File Upload Validation ✓
- CWE-436: Polyglot File Prevention ✓
- SHA-256: Hash Integrity ✓
- Deduplication: Same file detection ✓
