# EnderChest API — Bruno Collection

API test collection for the EnderChest Secure File Management System.
Covers authentication, RBAC authorization, file operations, and security tests.

## Setup

1. Download Bruno: https://www.usebruno.com/
2. Open Bruno → **Open Collection** → select this folder
3. Select environment **Local** (top right)
4. Create test files (see below)

## Test Files

Create these files in a `test-files/` subfolder inside this collection:

```bash
mkdir test-files

# Valid files
echo "%PDF-1.4 test content" > test-files/document.pdf
printf '\xFF\xD8\xFF\xE0' > test-files/photo.jpg

# Malicious files (for security tests)
printf 'MZ' > test-files/malware.exe
printf 'PK' > test-files/app.jar
echo "#!/bin/bash\nrm -rf /" > test-files/exploit.sh
echo "@echo off\ndel /f /s *" > test-files/script.bat
```

## Usage Flow

### 1 — Authenticate
Run one of the **Auth** requests to get a JWT token.
The token is saved automatically to `{{token}}`.

### 2 — Test file operations
Use **Files/Upload**, **Files/Download**, **Files/Delete** with the token.

### 3 — Test RBAC (ST-07)
| Request | OWNER | EDITOR | VIEWER | ADMIN | No token |
|---|---|---|---|---|---|
| Upload | 201 | 201 | 403 | 403 | 401 |
| Download | 200 | 200 | 200 | 403 | 401 |
| Delete | 200 | 403 | 403 | 403 | 401 |
| Admin health | 403 | 403 | 403 | 200 | 401 |

### 4 — Run security tests
All **Security** requests require an OWNER or EDITOR token.

## Folder Structure

```
EnderChest-Complete/
├── Auth/
│   ├── Get Token Owner.bru      — JWT for owner@test.com
│   ├── Get Token Admin.bru      — JWT for admin@test.com
│   ├── Get Token Editor.bru     — JWT for editor@test.com
│   └── Get Token Viewer.bru     — JWT for viewer@test.com
│
├── Admin/
│   ├── Admin Health Check.bru   — ST-07: RBAC on admin endpoint
│   └── No Auth 401 Test.bru     — ST-07: Unauthenticated = 401
│
├── Files/
│   ├── Upload/
│   │   ├── Upload Valid PDF.bru          — ST-03: Valid upload
│   │   ├── Upload Valid Image.bru        — ST-03: Valid JPEG upload
│   │   └── Viewer Cannot Upload 403.bru  — ST-07: VIEWER blocked
│   ├── Download/
│   │   └── Download File.bru             — Download by fileId
│   └── Delete/
│       ├── Delete File Owner.bru         — OWNER can delete
│       └── Editor Cannot Delete 403.bru  — ST-07: EDITOR blocked
│
├── Security/
│   ├── Path Traversal Double Dots.bru    — ST-01: AC-01 / T-05
│   ├── Path Traversal Absolute Path.bru  — ST-01: AC-01 / T-05
│   ├── Block EXE Upload.bru              — ST-03: AC-03 / T-06
│   ├── Block JAR Upload.bru              — ST-03: AC-03 / T-06
│   ├── Block Shell Script Upload.bru     — ST-03: AC-03 / T-06
│   ├── Block BAT Upload.bru              — ST-03: AC-03 / T-06
│   ├── Deduplication Same File.bru       — SHA-256 deduplication
│   └── Hash Verification SHA256.bru      — ST-12: SDR-NEW-11
│
├── environments/
│   └── Local.json                        — Environment variables
│
├── bruno.json                            — Collection config
└── README.md                             — This file
```

## Security Test Coverage

| Test | ST | SDR | Abuse Case | Threat |
|---|---|---|---|---|
| Path Traversal Double Dots | ST-01 | SDR-04 | AC-01 | T-05 |
| Path Traversal Absolute Path | ST-01 | SDR-04 | AC-01 | T-05 |
| Block EXE/JAR/SH/BAT Upload | ST-03 | SDR-05 | AC-03 | T-06 |
| Viewer Cannot Upload | ST-07 | SDR-02 | AC-07 | T-09 |
| Editor Cannot Delete | ST-07 | SDR-02 | AC-07 | T-09 |
| Admin Health — RBAC | ST-07 | SDR-02 | AC-11 | T-10 |
| No Auth → 401 | ST-07 | SDR-01 | — | T-04 |
| Hash Verification | ST-12 | SDR-NEW-11 | — | T-17 |
