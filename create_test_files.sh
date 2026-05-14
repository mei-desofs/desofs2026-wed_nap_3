#!/bin/bash

#############################################################################
# EnderChest Test Files Creator Script
#
# Purpose: Creates test files with proper magic bytes for security testing
#
# Files Created:
#  - document.pdf        (PDF with magic bytes)
#  - photo.png          (PNG with magic bytes)
#  - photo.jpg          (JPEG with magic bytes)
#  - malware.exe        (Windows executable with MZ header)
#  - script.bat         (Batch script)
#  - exploit.sh         (Shell script)
#  - app.jar            (JAR/ZIP with PK header)
#  - text.txt           (Plain text file)
#
# Usage: bash create_test_files.sh
#
#############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create test directory
TEST_DIR="test_files"

echo -e "${YELLOW}=== EnderChest Test Files Creator ===${NC}"
echo ""
echo "Creating test files in: ${TEST_DIR}/"
echo ""

# Create directory if it doesn't exist
if [ ! -d "$TEST_DIR" ]; then
    mkdir -p "$TEST_DIR"
    echo -e "${GREEN}✓${NC} Created directory: $TEST_DIR/"
else
    echo -e "${YELLOW}ℹ${NC} Directory already exists: $TEST_DIR/"
fi

# Function to create file with magic bytes
create_file_with_bytes() {
    local filename=$1
    local magic_bytes=$2
    local description=$3
    
    local filepath="$TEST_DIR/$filename"
    
    # Use printf to write binary magic bytes
    printf '%b' "$magic_bytes" > "$filepath"
    
    # Add some content to make files realistic
    if [ "$filename" == "malware.exe" ]; then
        # PE executable format
        echo "This is a test executable" >> "$filepath"
    elif [ "$filename" == "document.pdf" ]; then
        # Add PDF-like content
        echo "1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj" >> "$filepath"
        echo "2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj" >> "$filepath"
    elif [ "$filename" == "photo.png" ]; then
        # Add PNG-like content
        printf '\x00\x00\x00\rIHDR\x00\x00\x00\x01' >> "$filepath"
        printf '\x00\x00\x00\x01\x08\x06\x00\x00\x00' >> "$filepath"
        printf '\x1f\x15\xc4\x89' >> "$filepath"
    elif [ "$filename" == "photo.jpg" ]; then
        # Add minimal JPEG content
        echo "JPEG image data" >> "$filepath"
    elif [ "$filename" == "app.jar" ]; then
        # JAR is ZIP, add some content
        echo "Manifest-Version: 1.0" >> "$filepath"
        echo "Main-Class: Test" >> "$filepath"
    fi
    
    echo -e "${GREEN}✓${NC} Created $filename ($description)"
    ls -lh "$filepath"
}

# Create legitimate files with magic bytes

echo ""
echo "Creating LEGITIMATE FILES (should be accepted):"
echo "================================================"
echo ""

create_file_with_bytes "document.pdf" "%PDF-1.4\n" "PDF Document"

create_file_with_bytes "photo.png" "\x89PNG\r\n\x1a\n" "PNG Image"

create_file_with_bytes "photo.jpg" "\xFF\xD8\xFF\xE0\x00\x10JFIF" "JPEG Image"

create_file_with_bytes "text.txt" "This is a plain text file.\n" "Plain Text"

# Create malicious files with magic bytes

echo ""
echo "Creating MALICIOUS FILES (should be rejected):"
echo "=============================================="
echo ""

create_file_with_bytes "malware.exe" "MZ\x90\x00" "Windows Executable"

create_file_with_bytes "script.bat" "@echo off\r\necho test\r\n" "Batch Script"

create_file_with_bytes "exploit.sh" "#!/bin/bash\necho 'Exploit'\n" "Shell Script"

create_file_with_bytes "app.jar" "PK\x03\x04" "Java Archive (ZIP)"

# Create a file with misleading extension (file type mismatch)

echo ""
echo "Creating MISLEADING FILES (testing magic byte detection):"
echo "=========================================================="
echo ""

# PDF content but named as .exe
printf '%b' "%PDF-1.4\n" > "$TEST_DIR/fake-pdf.exe"
echo "This is actually a PDF inside an EXE" >> "$TEST_DIR/fake-pdf.exe"
echo -e "${GREEN}✓${NC} Created fake-pdf.exe (PDF content, .exe extension - should be detected)"

# EXE magic bytes but named as .pdf
printf '%b' "MZ\x90\x00" > "$TEST_DIR/fake-exe.pdf"
echo "This is actually an EXE inside a PDF" >> "$TEST_DIR/fake-exe.pdf"
echo -e "${GREEN}✓${NC} Created fake-exe.pdf (EXE content, .pdf extension - should be detected)"

# Summary

echo ""
echo "=== SUMMARY ===" 
echo ""
ls -lh "$TEST_DIR/" | tail -n +2
echo ""
echo -e "${YELLOW}File Count:${NC} $(ls "$TEST_DIR"/ | wc -l) files created"
echo ""

echo "FILE DESCRIPTIONS:"
echo "=================="
echo ""
echo "ACCEPTED FILES (Whitelisted MIME types):"
echo "  • document.pdf      - Valid PDF document"
echo "  • photo.png         - Valid PNG image"
echo "  • photo.jpg         - Valid JPEG image"
echo "  • text.txt          - Valid plain text file"
echo ""
echo "REJECTED FILES (Blacklisted MIME types):"
echo "  • malware.exe       - Windows executable (application/x-msdownload)"
echo "  • script.bat        - Batch script (application/x-msdos-program)"
echo "  • exploit.sh        - Shell script (application/x-shellscript)"
echo "  • app.jar           - Java archive (application/java-archive)"
echo ""
echo "MAGIC BYTE TEST FILES:"
echo "  • fake-pdf.exe      - PDF magic bytes with .exe extension"
echo "  • fake-exe.pdf      - EXE magic bytes with .pdf extension"
echo ""

echo -e "${GREEN}=== Test files created successfully ===${NC}"
echo ""
echo "Next steps:"
echo "1. Set environment variable: export TEST_FILES_DIR=\"$(pwd)/test_files\""
echo "2. Run MANUAL_TESTING_GUIDE.md tests"
echo "3. Or import EndercChest_FileStorage_Tests.postman_collection.json into Postman"
echo ""
