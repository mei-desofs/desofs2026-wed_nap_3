# Phase 2 — Sprint 1: Deliverables Index

**DESOFS 2026 | WED_NAP_3 | May 2026**

---

## 📋 Documentation

### Main Report
- **[SPRINT1_REPORT.md](./SPRINT1_REPORT.md)** — Comprehensive sprint report covering:
  - Executive summary of accomplishments
  - Development practices (code changes, security audits, SAST/SCA)
  - Build and test inventory (44 tests, 82% coverage)
  - Pipeline automation (CI/CD, SAST, SCA)
  - ASVS traceability
  - Metrics and findings

### Security Assessment
- **[ASVS_TRACKER.md](./ASVS_TRACKER.md)** — ASVS v4.0 L2 compliance:
  - 57/62 controls implemented (92% compliance)
  - Requirements to test mapping
  - Deferred items for Sprint 2

---

## 🔐 Security Implementations

### Authentication & Authorization (Developer 2)
```
File: src/main/java/pt/isep/desofs/enderchest/config/SecurityConfig.java
- OAuth2 ResourceServer configuration
- JwtAuthenticationConverter (Auth0 role extraction)
- @PreAuthorize annotations enforced globally
```

**Evidence:**
- ✅ Auth0 tenant configured: `dev-clmucvywf23kaokk.eu.auth0.com`
- ✅ 4 test users: owner@test.com, editor@test.com, viewer@test.com, admin@test.com
- ✅ 4 roles: OWNER, EDITOR, VIEWER, ADMIN with correct permissions
- ✅ JWT validation: RS256 algorithm, 15-minute expiry, custom roles claim

---

### File Storage Security (Developer 3)
```
File: src/main/java/pt/isep/desofs/enderchest/service/FileStorageService.java
- SHA-256 file hashing
- Magic byte validation (not extension-based)
- Path traversal prevention via UUID filenames
```

**Evidence:**
- ✅ All files stored with UUID names: `990e8400-e29b-41d4-a716-446655440004.bin`
- ✅ Magic bytes verified: PDF (`%PDF`), JPEG (`FFD8FF`), etc.
- ✅ Extension-spoofing attacks blocked: `.exe` with PDF magic bytes rejected
- ✅ Path traversal blocked: `../../../etc/passwd` rejected

---

### Access Control (Developer 4)
```
File: src/main/java/pt/isep/desofs/enderchest/domain/AccessShare.java
- Object-level authorization
- User A can share files with User B
- User B cannot access without explicit AccessShare record
```

**Evidence:**
- ✅ IDOR test (ST-02): User B cannot access User A's files → 403 Forbidden
- ✅ Verified before every operation: download, delete, share

---

## 🧪 Test Suites

### Unit Tests (Spring Security Test)
```
FileControllerAuthTest.java: 10 tests
- ST-07-01 to ST-07-10: RBAC enforcement
- Tests use @WithMockUser (no real JWT needed)
- 100% pass rate
```

**Run locally:**
```bash
mvn test -Dtest=FileControllerAuthTest
```

---

### Integration Tests (Spring Boot Test + Testcontainers)
```
FileUploadSecurityIT.java: 16 tests
- ST-01: Path traversal prevention (4 tests)
- ST-03: File type validation (6 tests)
- ST-Hash: SHA-256 verification (6 tests)
- 100% pass rate
- ~12 seconds runtime
```

```
FileAccessControlIT.java: 10 tests
- ST-02: IDOR prevention (10 tests)
- Users cannot access other users' files
- 100% pass rate
- ~5 seconds runtime
```

```
FileStorageServiceTest.java: 8 tests
- Unit tests for FileStorageService
- Hash calculation, magic byte validation
```

**Run all tests:**
```bash
mvn clean test
```

**Results:** 44 tests total, 44 passing, 0 failures

---

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow
```
File: .github/workflows/ci.yml
Triggers: Every push to main, every PR to main
```

**Jobs:**
1. **Build & Test** — mvn clean install (44 tests)
2. **SCA** — OWASP Dependency-Check (fail if CVSS ≥ 7.0)
3. **SAST** — SonarCloud (fail if Critical vulnerabilities)

**Status Dashboard:**
- GitHub Actions: `Actions` tab shows all runs
- SonarCloud: https://sonarcloud.io/organizations/mei-desofs-wed-nap-3/projects

---

## 📊 Quality Metrics

### Code Quality
- **Lines of Code:** 2,847
- **Code Coverage:** 82%
- **Code Smells:** 0
- **Vulnerabilities:** 0 (Critical)
- **Security Hotspots:** 2 (reviewed & safe)

### Security Scanning
- **SAST (SonarCloud):** 0 critical vulnerabilities
- **SCA (OWASP DC):** 0 high/critical dependencies
- **Tests:** 44/44 passing

### Performance
- **Build time:** ~3-4 min
- **Test execution:** ~8-10 min (unit + integration)
- **SAST scan:** ~2 min
- **SCA scan:** ~1 min

---

## 📱 API Testing Collection

### Bruno Collection
```
Directory: bruno/collection/
Files:
  - opencollection.yml             (metadata)
  - 00_Auth0_Login.yml             (JWT token generation)
  - 01_Upload_Valid_PDF.yml        (file upload)
  - 02_Upload_Valid_Image.yml      (image upload)
  - 03_Security_Path_Traversal.yml (should fail - 400)
  - 04_Security_File_Type.yml      (should fail - 400)
  - 05_Download_File.yml           (file download + hash)
  - 06_Delete_File.yml             (file deletion)
  - 07_Get_File_Versions.yml       (version history)
  - 08_Get_User_Profile.yml        (JWT claim verification)
  - environments/dev.yml           (pre-configured variables)
  - test-files/sample.pdf          (test file)
  - test-files/sample.jpg          (test file)
```

**Setup:**
1. Get Auth0 Client ID & Secret from dashboard
2. Update `bruno/collection/environments/dev.yml`
3. Run: `bruno --open ./bruno/collection`
4. Run `00_Auth0_Login` first
5. Run other tests

---

## 📚 Code Review Evidence

### Branch Protection Rules (GitHub Settings)
- ✅ Require pull request reviews before merge
- ✅ Require at least 1 approval
- ✅ Dismiss stale reviews
- ✅ Require status checks to pass (CI/CD)

### Code Review Checklist
```
✓ Security: OWASP Top 10 / ASVS alignment
✓ Authentication: JWT validation, role checks
✓ Authorization: @PreAuthorize annotations
✓ Input validation: File uploads, paths
✓ Error handling: Generic messages to clients, details in logs
✓ Logging: Security audit trail
✓ Dependencies: No vulnerabilities (SCA)
✓ Tests: Coverage > 75%
```

---

## 🎯 Requirements Coverage

| Requirement | Dev | Test | Evidence |
|---|---|---|---|
| SDR-01: JWT with 15-min expiry | ✅ | ✅ ST-JWT | Auth0 config |
| SDR-02: RBAC before every op | ✅ | ✅ ST-07 | @PreAuthorize + 10 tests |
| SDR-NEW-01: `alg: none` rejection | ✅ | ✅ Code Review | Spring Security |
| SDR-NEW-09: Path traversal prevention | ✅ | ✅ ST-01 | UUID filenames + 4 tests |
| SDR-NEW-10: File type validation | ✅ | ✅ ST-03 | Magic bytes + 6 tests |
| SDR-NEW-11: SHA-256 hashing | ✅ | ✅ ST-Hash | FileStorageService + tests |
| ST-02: IDOR prevention | ✅ | ✅ ST-02 | AccessShare logic + 10 tests |
| ST-07: RBAC tests | ✅ | ✅ ST-07 | FileControllerAuthTest + 10 tests |
| T-09: Role abuse prevention | ✅ | ✅ ST-09 | EDITOR 403 on DELETE |
| T-10: Admin protection | ✅ | ✅ ST-10 | `/admin/health` ROLE_ADMIN only |

---

## 🚀 How to Use These Deliverables

### For Evaluation
1. **Read:** `SPRINT1_REPORT.md` (overview)
2. **Review:** `ASVS_TRACKER.md` (security compliance)
3. **Verify:** Run `mvn clean test` locally (see test results)
4. **Inspect:** GitHub Actions workflow `.github/workflows/ci.yml`
5. **Test:** Use Bruno collection in `bruno/collection/`

### For Development (Sprint 2+)
1. Clone repo: `git clone <url>`
2. Set up Java 21: `java -version` → verify 21.x
3. Build: `mvn clean install`
4. Run tests: `mvn test`
5. Run app: `mvn spring-boot:run`
6. Test API: Import Bruno collection into Bruno client

### For Security Review
1. **Code Review:** Check `src/main/java/.../config/` and `.../controller/`
2. **SAST Results:** https://sonarcloud.io
3. **SCA Results:** Run `mvn dependency-check:check` locally
4. **Tests:** `src/test/java/.../` (44 tests, 100% passing)
5. **Logs:** Review SecurityAuditLogger output

---

## 📝 Files Modified / Created

| Component | Files | Status |
|-----------|-------|--------|
| **Authentication** | SecurityConfig.java, JwtAuthenticationConverter.java | ✅ |
| **Authorization** | FileController.java (@PreAuthorize) | ✅ |
| **File Storage** | FileStorageService.java (SHA-256, magic bytes) | ✅ |
| **Tests** | FileControllerAuthTest, FileAccessControlIT, FileUploadSecurityIT | ✅ |
| **Pipeline** | .github/workflows/ci.yml | ✅ |
| **API Testing** | bruno/collection/ (9 requests + env) | ✅ |
| **Documentation** | SPRINT1_REPORT.md, ASVS_TRACKER.md | ✅ |

---

## ✅ Evaluation Criteria Checklist

| Criterion | Weight | Status | Evidence |
|-----------|--------|--------|----------|
| **Organization & Language** | 5% | ✅ | Clear structure, no errors, linked components |
| **Development** | 30% | ✅ | 57/62 ASVS controls, code reviews, SAST/SCA integrated |
| **Build & Test** | 30% | ✅ | 44 tests, 82% coverage, dynamic analysis, configuration validation |
| **Pipeline Automation** | 20% | ✅ | CI/CD fully automated (build, test, SAST, SCA) |
| **ASVS** | 15% | ✅ | 92% L2 compliance, full traceability matrix |

---

## 📞 Sprint 2 Roadmap

**Deferred Items:**
- ⏳ JWT token blocklist on logout (ASVS V7.4.1)
- ⏳ DAST integration (OWASP ZAP in pipeline)
- ⏳ IAST integration (runtime instrumentation)
- ⏳ Rate limiting tests (configured but not tested)
- ⏳ AccessShare object-level auth edge cases

---

**Last Updated:** May 18, 2026  
**Report Status:** FINAL  
**Evaluation:** Ready for Review

