# Phase 2 — Sprint 1: Deliverables Index

**DESOFS 2026 | WED_NAP_3 | May 2026**

---

## Documentation

- **[SPRINT1_REPORT.md](./SPRINT1_REPORT.md)** — Sprint report covering development, security implementation, testing, and CI/CD pipeline

---

## Security Implementations

### Authentication & Authorization
```
src/main/java/pt/isep/desofs/enderchest/config/SecurityConfig.java
```
- OAuth2 Resource Server with Auth0 (RS256)
- Custom `JwtAuthenticationConverter` extracting roles from `https://enderchest-api/roles`
- `@PreAuthorize` on all controller endpoints
- Stateless sessions, CSRF disabled

### File Storage Security
```
src/main/java/pt/isep/desofs/enderchest/service/FileStorageService.java
```
- SHA-256 integrity hashing
- Magic byte validation (not extension-based)
- Path traversal prevention via UUID filenames
- Deduplication by hash
- Per-user storage quota enforcement

### Access Control (IDOR Prevention)
```
src/main/java/pt/isep/desofs/enderchest/service/FileService.java
```
- Object-level authorization before download/delete
- Ownership check (JWT subject matches `uploadedBy`)
- AccessShare lookup for shared access grants

---

## Test Suites

| Test Class | Tests | Type | Focus |
|------------|-------|------|-------|
| `FileControllerAuthTest` | 10 | Unit (MockMvc) | RBAC enforcement (ST-07) |
| `FileAccessControlIT` | 11 | Integration | IDOR prevention (ST-02) |
| `FileUploadSecurityIT` | 16 | Integration | Path traversal, file type, hashing |
| `FileStorageServiceTest` | 16 | Unit (Mockito) | Service-layer logic |
| **Total** | **53** | | **100% pass rate** |

### Run all tests
```bash
mvn clean verify -Dspring.profiles.active=test '-Dsurefire.includes=**/*Test.java,**/*IT.java'
```

### Coverage
- **Overall:** 27.0% (1,340 / 4,966 instructions)
- **Security-critical classes:** 50–82% (FileService 77%, FileStorageService 70%, FileController 50%)

---

## CI/CD Pipeline

**File:** `.github/workflows/ci.yml`

| Job | Purpose | Quality Gate |
|-----|---------|--------------|
| build-and-test | Compile + run 53 tests | Any test failure fails the build |
| sca | OWASP Dependency-Check v10.0.4 | CVSS ≥ 7.0 fails the build |
| sonar | SonarCloud SAST | Critical vulnerabilities block merge |

---

## API Testing Collection (Bruno)

**Directory:** `bruno/collection/` — 21 pre-configured requests

| Category | Requests |
|----------|----------|
| Auth | 4 (token generation per role) |
| Files/Upload | 3 |
| Files/Download | 1 |
| Files/Delete | 2 |
| Admin | 2 |
| Security | 8 (path traversal, blocked extensions, dedup, hash) |

**Setup:**
1. Install [Bruno](https://www.usebruno.com/)
2. Open collection: `bruno/collection/`
3. Select environment: `Local`
4. Run Auth requests first to obtain tokens

---

## How to Run

### Prerequisites
- Java 21
- Maven 3.9+
- PostgreSQL (or use H2 for tests via `application-test.properties`)

### Build & Test
```bash
mvn clean verify -Dspring.profiles.active=test '-Dsurefire.includes=**/*Test.java,**/*IT.java'
```

### Run Application
```bash
mvn spring-boot:run
```

### Security Scans
```bash
# SCA — OWASP Dependency-Check
mvn dependency-check:check

# Coverage report
mvn verify  # report at target/site/jacoco/index.html
```

---

## Sprint 2 Roadmap

- JWT token blocklist on logout
- OWASP ZAP (DAST) integration in CI
- ELK stack for centralised logging and security monitoring
- Rate limiting automated tests
- Increase test coverage for uncovered services

---

**Last Updated:** May 18, 2026
