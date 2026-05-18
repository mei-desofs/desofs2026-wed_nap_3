# Phase 2 — Sprint 1: Development and Security Testing Report

**Course:** DESOFS 2026  
**Group:** WED_NAP_3  
**Sprint:** Phase 2 — Sprint 1  
**Date:** May 2026  

---

## 1. Introduction

### 1.1 Purpose

This report documents the development, security implementation, and testing activities performed during Sprint 1 of Phase 2. It presents the DevSecOps pipeline configuration, authentication and authorization implementation, file storage security controls, and the automated testing strategy adopted to ensure compliance with the Application Security Verification Standard (ASVS) v4.0.

### 1.2 Scope

The sprint delivered four primary work streams:

1. **CI/CD Pipeline** — Automated build, SAST (SonarCloud), and SCA (OWASP Dependency-Check)
2. **Authentication & Authorization** — Auth0 OAuth2 integration with role-based access control (RBAC)
3. **File Storage Security** — SHA-256 integrity hashing, magic byte validation, path traversal prevention
4. **Security Testing** — Automated unit and integration tests targeting OWASP Top 10 vulnerabilities

### 1.3 Repository Structure

```
enderchest/
├── .github/workflows/ci.yml              # CI/CD Pipeline (3 jobs)
├── src/main/java/pt/isep/desofs/enderchest/
│   ├── config/SecurityConfig.java        # OAuth2 + RBAC configuration
│   ├── config/ApiExceptionHandler.java   # Global exception handling
│   ├── controller/FileController.java    # REST API with @PreAuthorize
│   ├── entity/                           # JPA entities (File, User, AccessShare, Folder)
│   ├── service/FileStorageService.java   # File operations with security controls
│   └── service/FileService.java          # Access control (IDOR prevention)
├── src/test/java/pt/isep/desofs/enderchest/
│   ├── controller/FileControllerAuthTest.java  # RBAC tests (ST-07)
│   ├── controller/FileAccessControlIT.java     # IDOR tests (ST-02)
│   ├── integration/FileUploadSecurityIT.java   # File security tests (ST-01, ST-03–ST-06)
│   └── service/FileStorageServiceTest.java     # Unit tests (upload, dedup, delete)
├── bruno/collection/                     # API testing collection (21 requests)
├── pom.xml                               # Maven build with SCA + JaCoCo plugins
└── Deliverables/Phase2/Sprint1/          # This report
```

### 1.4 Codebase Metrics

| Metric | Value |
|--------|-------|
| Java source files | 55 |
| Lines of code (src/main) | 7,431 |
| Test classes | 4 |
| Total test methods | 53 |

---

## 2. Development

### 2.1 Authentication and Authorization (OAuth2 + RBAC)

#### 2.1.1 Security Configuration

**File:** `src/main/java/pt/isep/desofs/enderchest/config/SecurityConfig.java`

The application uses Spring Security's OAuth2 Resource Server with Auth0 as the identity provider. A custom `JwtAuthenticationConverter` extracts roles from the Auth0 custom claim namespace and maps them to Spring Security `GrantedAuthority` objects:

```java
private static final String ROLES_CLAIM = "https://enderchest-api/roles";

converter.setJwtGrantedAuthoritiesConverter(jwt -> {
    List<String> roles = jwt.getClaimAsStringList(ROLES_CLAIM);
    if (roles == null || roles.isEmpty()) {
        return Collections.emptyList();
    }
    return roles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
            .collect(Collectors.toList());
});
```

Security properties enforced:
- **Stateless sessions** — `SessionCreationPolicy.STATELESS` (no HTTP sessions)
- **CSRF disabled** — appropriate for a stateless API that does not use cookies
- **All endpoints authenticated** — except Swagger UI documentation paths
- **Method-level security** — `@EnableMethodSecurity(prePostEnabled = true)`

#### 2.1.2 RBAC Enforcement

**File:** `src/main/java/pt/isep/desofs/enderchest/controller/FileController.java`

Each endpoint is protected with `@PreAuthorize` annotations enforcing the principle of least privilege:

| Endpoint | Allowed Roles | Threat Mitigated |
|----------|---------------|------------------|
| `POST /api/v1/files/upload` | OWNER, EDITOR | T-09: VIEWER cannot upload |
| `GET /api/v1/files/{fileId}` | OWNER, EDITOR, VIEWER | SDR-02: Read access |
| `DELETE /api/v1/files/{fileId}` | OWNER | T-09: EDITOR cannot delete |
| `GET /api/v1/files/admin/health` | ADMIN | T-10: Admin-only endpoint |

#### 2.1.3 User Identity Extraction

User identity is derived exclusively from the JWT `sub` (subject) claim, preventing header forgery attacks:

```java
// Secure: identity from cryptographically signed JWT
String userId = jwt.getSubject(); // e.g., "auth0|6a05a12ff53eb09287768800"
```

This replaces a prior insecure pattern where the userId was extracted from a client-supplied `X-User-Id` header.

### 2.2 File Storage Security

**File:** `src/main/java/pt/isep/desofs/enderchest/service/FileStorageService.java`

#### 2.2.1 SHA-256 Integrity Hashing

Every uploaded file receives a SHA-256 hash computed from its byte content. This hash is persisted alongside the file metadata, enabling integrity verification on download.

#### 2.2.2 Magic Byte Validation

File type validation is performed using magic byte (file signature) analysis rather than extension-based detection. This prevents bypasses where an attacker renames an executable to `.pdf`.

Blocked file types: `.exe`, `.bat`, `.sh`, `.jar`, `.com`, `.cmd`, `.msi`

#### 2.2.3 Path Traversal Prevention

Filenames are sanitised to prevent directory traversal attacks. The system rejects filenames containing `../`, `..\\`, absolute paths (`/`, `C:\`), and stores files using UUID-based names that cannot be controlled by the client.

#### 2.2.4 Deduplication

Files are deduplicated by SHA-256 hash. If a file with an identical hash already exists (including soft-deleted files), the system returns a reference to the existing file rather than storing a duplicate.

#### 2.2.5 Storage Quota Enforcement

Per-user storage quotas are enforced before file persistence, preventing resource exhaustion attacks.

### 2.3 Access Control (IDOR Prevention)

**File:** `src/main/java/pt/isep/desofs/enderchest/service/FileService.java`

Object-level authorization prevents Insecure Direct Object Reference (IDOR) attacks through two verification layers:

1. **Ownership check:** `file.getUploadedBy().equals(userId)` — the file uploader always has access
2. **AccessShare check:** queries the `access_shares` table for explicit grants (OWNER, EDITOR, VIEWER roles at the object level)

### 2.4 Global Exception Handling

**File:** `src/main/java/pt/isep/desofs/enderchest/config/ApiExceptionHandler.java`

A `@ControllerAdvice` class ensures that:
- `FileNotFoundException` returns HTTP 404
- `FileAccessDeniedException` returns HTTP 403
- `AccessDeniedException` (Spring Security) is re-thrown for proper 403 handling
- `InvalidFileTypeException` returns HTTP 415
- `PathTraversalAttemptException` returns HTTP 400
- `StorageQuotaExceededException` returns HTTP 413
- Generic exceptions return HTTP 500 without leaking internal details

---

## 3. Build and Test

### 3.1 Test Inventory

| Test Class | Tests | Type | Focus Area |
|------------|-------|------|------------|
| `FileControllerAuthTest` | 10 | Unit (MockMvc + @WithMockUser) | RBAC enforcement (ST-07) |
| `FileAccessControlIT` | 11 | Integration (SpringBootTest + jwt()) | IDOR prevention (ST-02) |
| `FileUploadSecurityIT` | 17 | Integration (SpringBootTest) | Path traversal, file type, hashing (ST-01, ST-03–ST-06) |
| `FileStorageServiceTest` | 16 | Unit (Mockito) | Service-layer logic |
| **Total** | **53** | | |

### 3.2 Test Results — RBAC Enforcement (ST-07)

**Class:** `FileControllerAuthTest.java` — 10 tests, 0 failures

| ID | Test Case | Expected | Result |
|----|-----------|----------|--------|
| ST-07-01 | ADMIN accesses `/admin/health` | 200 OK | Pass |
| ST-07-02 | OWNER accesses `/admin/health` | 403 Forbidden | Pass |
| ST-07-03 | EDITOR accesses `/admin/health` | 403 Forbidden | Pass |
| ST-07-04 | VIEWER accesses `/admin/health` | 403 Forbidden | Pass |
| ST-07-05 | Unauthenticated access | 401 Unauthorized | Pass |
| ST-07-06 | EDITOR attempts file deletion | 403 Forbidden | Pass |
| ST-07-07 | VIEWER attempts file deletion | 403 Forbidden | Pass |
| ST-07-08 | Unauthenticated file deletion | 401 Unauthorized | Pass |
| ST-07-09 | Unauthenticated file download | 401 Unauthorized | Pass |
| ST-07-10 | ADMIN attempts file deletion | 403 Forbidden | Pass |

### 3.3 Test Results — IDOR Prevention (ST-02)

**Class:** `FileAccessControlIT.java` — 11 tests, 0 failures

| ID | Test Case | Expected | Result |
|----|-----------|----------|--------|
| ST-02-01 | User B downloads User A's file (no AccessShare) | 403 Forbidden | Pass |
| ST-02-02 | User A downloads own file (uploader check) | 404 (IDOR passed, no file on disk) | Pass |
| ST-02-03 | User B with VIEWER AccessShare downloads | 404 (IDOR passed) | Pass |
| ST-02-04 | User B with EDITOR AccessShare downloads | 404 (IDOR passed) | Pass |
| ST-02-05 | User B deletes User A's file (no AccessShare) | 403 Forbidden | Pass |
| ST-02-06 | User A deletes own file | 200 OK | Pass |
| ST-02-07 | User B with VIEWER AccessShare deletes | 403 Forbidden | Pass |
| ST-02-08 | User B with EDITOR AccessShare deletes | 403 Forbidden | Pass |
| ST-02-09 | User B with OWNER AccessShare deletes | 200 OK | Pass |
| ST-02-10 | Unauthenticated download | 401 Unauthorized | Pass |
| ST-02-11 | Unauthenticated delete | 401 Unauthorized | Pass |

### 3.4 Test Results — File Upload Security (ST-01, ST-03–ST-06)

**Class:** `FileUploadSecurityIT.java` — 16 tests, 0 failures

| ID | Test Case | Expected | Result |
|----|-----------|----------|--------|
| ST-01-A | Path traversal with `../` | PathTraversalAttemptException | Pass |
| ST-01-B | Path traversal with `/` | PathTraversalAttemptException | Pass |
| ST-01-C | Windows absolute path | PathTraversalAttemptException | Pass |
| ST-01-D | Backslash traversal | PathTraversalAttemptException | Pass |
| ST-01-E | Valid filename upload | 201 Created | Pass |
| ST-03-A | Executable file (.exe) | InvalidFileTypeException | Pass |
| ST-03-B | Batch script (.bat) | InvalidFileTypeException | Pass |
| ST-03-C | Shell script (.sh) | InvalidFileTypeException | Pass |
| ST-03-D | JAR file (.jar) | InvalidFileTypeException | Pass |
| ST-03-E | Valid PDF file | 201 Created | Pass |
| ST-03-F | Valid JPEG image | 201 Created | Pass |
| ST-04-A | Duplicate file upload (deduplication) | Returns existing file ID | Pass |
| ST-05-A | Soft delete file | File marked as deleted | Pass |
| ST-05-B | Retrieve soft-deleted file | Failure (file not accessible) | Pass |
| ST-06-A | SHA-256 hash validity | Valid 64-char hex string | Pass |
| ST-06-B | Hash persistence in database | Hash stored correctly | Pass |

### 3.5 Test Results — Service Unit Tests

**Class:** `FileStorageServiceTest.java` — 16 tests, 0 failures

| ID | Test Case | Result |
|----|-----------|--------|
| 1 | Upload valid file with SHA-256 hash | Pass |
| 2 | Path traversal detection (..) | Pass |
| 3 | Path traversal detection (/) | Pass |
| 4 | Invalid MIME type rejection (T-06) | Pass |
| 5 | File size limit enforcement | Pass |
| 6 | Null filename rejection | Pass |
| 7 | Empty filename rejection | Pass |
| 8 | Duplicate file detection by hash | Pass |
| 9 | Soft-deleted file restoration on duplicate | Pass |
| 10 | File retrieval with integrity verification | Pass |
| 11 | Non-existent file retrieval rejection | Pass |
| 12 | Unauthorized user retrieval rejection | Pass |
| 13 | Soft-delete with version entry | Pass |
| 14 | Non-owner deletion rejection | Pass |
| 15 | Already-deleted file rejection | Pass |
| 16 | Legacy save() backward compatibility | Pass |

### 3.6 Code Coverage

JaCoCo instruction coverage from a full local build including all 4 test classes (53 tests):

| Metric | Value |
|--------|-------|
| Instructions covered | 1,340 / 4,966 |
| Overall coverage | 27.0% |

**Per-class highlights:**

| Class | Coverage |
|-------|----------|
| `FileStorageService` | 70% (581/829) |
| `FileService` | 77% (179/233) |
| `SecurityConfig` | 75% (75/100) |
| `FileController` | 50% (102/204) |
| `File` (entity) | 82% (66/80) |

**Note:** Classes without dedicated tests (`FolderService`, `AuditLogService`, `AccessShareController`, `FileVersionController`, `FolderController`) contribute 0–3% each, significantly reducing the aggregate figure. The security-critical classes under test achieve 50–82% coverage.

---

## 4. CI/CD Pipeline

### 4.1 Architecture

**File:** `.github/workflows/ci.yml`

The pipeline consists of three jobs triggered on every push to `main` and every pull request:

```
┌─────────────────┐      ┌──────────────────────┐      ┌─────────────────────┐
│ build-and-test  │─────▶│ sca                  │      │ sonar               │
│ (compile + test)│      │ (Dependency-Check)   │      │ (SonarCloud SAST)   │
└─────────────────┘      └──────────────────────┘      └─────────────────────┘
        │                                                        ▲
        └────────────────────────────────────────────────────────┘
                         needs: build-and-test
```

### 4.2 Job 1: Build and Test

```yaml
runs-on: ubuntu-latest
steps:
  - Checkout source (actions/checkout@v4)
  - Set up Java 21 (Temurin, Maven cached)
  - Run: mvn -B clean install
```

- Compiles all source code
- Executes all 53 automated tests
- Fails the pipeline on any test failure
- Uses `application-test.properties` with H2 in-memory database

### 4.3 Job 2: SCA — OWASP Dependency-Check

```yaml
needs: build-and-test
steps:
  - OWASP Dependency-Check Maven plugin (v10.0.4)
  - Quality Gate: Fail if CVSS >= 7.0 (HIGH severity)
  - Upload report artifact (retention: 30 days)
  - NVD cache: weekly refresh via actions/cache@v4
```

**Configuration (pom.xml):**
```xml
<artifactId>dependency-check-maven</artifactId>
<version>10.0.4</version>
<configuration>
    <failBuildOnCVSS>7</failBuildOnCVSS>
</configuration>
```

### 4.4 Job 3: SAST — SonarCloud

```yaml
needs: build-and-test
steps:
  - Build with coverage: mvn -B verify sonar:sonar
  - Project: mei-desofs-wed-nap-3_mei-desofs-wed-nap-3-sonarqube
  - SonarCloud Quality Gate enforcement
```

Quality Gate conditions:
- No new Critical vulnerabilities
- No new Blocker issues
- Coverage threshold enforcement

### 4.5 Caching Strategy

| Cache | Key | Purpose |
|-------|-----|---------|
| Maven dependencies | `${{ runner.os }}-maven-${{ hashFiles('pom.xml') }}` | Skip dependency download |
| NVD database | `owasp-nvd-${{ runner.os }}-${{ date +%Y-%U }}` | Weekly vulnerability DB refresh |
| SonarCloud packages | `${{ runner.os }}-sonar` | Faster analysis |

---

## 5. API Testing Collection (Bruno)

### 5.1 Collection Overview

A Bruno API collection with 21 pre-configured requests is provided for manual and exploratory testing:

| Category | Requests | Purpose |
|----------|----------|---------|
| Auth | 4 | Token generation for each role (Admin, Owner, Editor, Viewer) |
| Files/Upload | 3 | Upload valid image, valid PDF, VIEWER-denied upload |
| Files/Download | 1 | Download file by ID |
| Files/Delete | 2 | Owner deletion, Editor-denied deletion |
| Admin | 2 | Admin health check, unauthenticated 401 test |
| Security | 8 | Path traversal, blocked extensions, deduplication, hash verification |

### 5.2 Collection Location

```
bruno/collection/
├── Auth/           (Get Token Admin, Editor, Owner, Viewer)
├── Files/
│   ├── Upload/     (Upload Valid Image, Upload Valid PDF, Viewer Cannot Upload 403)
│   ├── Download/   (Download File)
│   └── Delete/     (Delete File Owner, Editor Cannot Delete 403)
├── Admin/          (Admin Health Check, No Auth 401 Test)
├── Security/       (Path Traversal, Block EXE/BAT/JAR/Shell, Dedup, Hash Verification)
└── environments/   (Local — base_url: http://localhost:8080)
```

---

## 6. Development Practices

### 7.1 Code Review Process

- GitHub branch protection rules require at least one approval per pull request
- All pushes to `main` trigger the CI pipeline (build, test, SAST, SCA)
- PRs are blocked if the pipeline fails

### 7.2 Static Analysis (SAST)

SonarCloud is configured to analyse on every build:
- **Project key:** `mei-desofs-wed-nap-3_mei-desofs-wed-nap-3-sonarqube`
- Quality Gate blocks merges on new critical vulnerabilities
- Integrated with JaCoCo for coverage reporting

### 7.3 Software Composition Analysis (SCA)

OWASP Dependency-Check (v10.0.4) scans all Maven dependencies:
- Fails the build on CVSS ≥ 7.0 (HIGH severity threshold)
- NVD database cached weekly for performance
- HTML report archived as GitHub Actions artifact (30-day retention)

### 7.4 Security Audit Logging

The `AuditLogService` records security-relevant events including authentication attempts, file access, and authorization failures, supporting forensic analysis and compliance requirements.

---

## 7. Known Limitations and Future Work

| Area | Current State | Planned (Sprint 2+) |
|------|---------------|---------------------|
| Token revocation | No logout blocklist | JWT blocklist on logout (ASVS V7.4.1) |
| DAST | Not integrated | OWASP ZAP in CI pipeline |
| IAST | Not integrated | Runtime instrumentation |
| Rate limiting | Configured but not tested | Automated rate limit tests |
| Coverage reporting | 27% overall (security-critical classes 50–82%) | Enforce minimum coverage threshold in CI |
| Centralised logging | Application logs to stdout only | ELK stack (Elasticsearch, Logstash, Kibana) for aggregated log analysis and security monitoring |

---

## 8. Conclusion

Sprint 1 delivered a functional DevSecOps pipeline with comprehensive security controls across authentication, authorization, and file storage. The 53 automated tests (100% pass rate) verify RBAC enforcement, IDOR prevention, path traversal blocking, file type validation, SHA-256 hashing, deduplication, and soft-delete functionality. The CI/CD pipeline automates build verification, static analysis, and dependency scanning on every commit.

---

**Report Date:** May 18, 2026  
**Team:** WED_NAP_3  
**Course:** DESOFS 2026
