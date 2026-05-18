# Pipeline Architecture — Decision Record

**Developer 1 — The Pipeline Architect**
**Phase 2, Sprint 1 | DESOFS 2026**

---

## 1. Scope

This document records the technical decisions made when designing the CI/CD pipeline for EnderChest. It covers job structure, tool selection, threshold choices, and configuration rationale so that the decisions can be evaluated and revisited.

Files created/modified:

| File | Purpose |
|---|---|
| `.github/workflows/ci.yml` | The pipeline definition |
| `pom.xml` | OWASP DC, JaCoCo, and SonarCloud Maven configuration |
| `owasp-suppressions.xml` | Documented false-positive suppressions for OWASP DC |

---

## 2. Pipeline Structure

### 2.1 Job Dependency Graph

```mermaid
flowchart TD
    trigger([Push / Pull Request to main])
    trigger --> build

    build["Job 1 — Build & Test\nmvn clean install\nH2 in-memory DB · JaCoCo coverage"]

    build --> sca
    build --> sonar
    build --> trivy

    sca["Job 2 — SCA\nOWASP Dependency-Check\nFails on CVSS ≥ 7.0"]
    sonar["Job 3 — SAST\nSonarCloud\nCode quality + security rules"]
    trivy["Job 4 — Container Scan\nTrivy\nFails on HIGH/CRITICAL CVEs\nwith a known fix available"]

    sca --> report[/"OWASP HTML Report\nArtifact · 30 days"/]
```

**Rationale:** Jobs 2, 3, and 4 run in parallel to keep total pipeline time low. All three are gated behind `build-and-test` because analyzing code that does not compile is wasteful, and a failing test suite should block the pipeline before expensive security scans run.

### 2.2 Trigger Strategy

The pipeline triggers on **every push and every pull request targeting `main`**. This enforces security gates at PR time before any code reaches the main branch.

### 2.3 Test Database

Tests use an H2 in-memory database configured in `src/test/resources/application-test.properties`. No PostgreSQL service container is needed in CI. The JWT JWK set URI is overridden with a local placeholder — tests using `@WithMockUser` never contact the Auth0 IdP, so the pipeline has no external dependencies at runtime.

---

## 3. Software Composition Analysis (SCA) — OWASP Dependency-Check

### 3.1 Tool Choice

**Chosen over:** Snyk.

OWASP Dependency-Check is open source, integrates directly with Maven, and sources its vulnerability database from the NVD. Snyk provides better developer UX (inline PR comments) but requires a team account and billing decision. OWASP DC can be replaced with Snyk in a future sprint if needed.

### 3.2 CVSS Threshold: 7.0

`failBuildOnCVSS=7` rejects any dependency with a CVSS v3 base score ≥ 7.0.

- CVSS 7.0 is the boundary between **Medium** (4.0–6.9) and **High** (7.0–8.9).
- All CRITICAL and HIGH vulnerabilities block the build.
- Medium findings are reported but do not block — many are context-dependent and not exploitable in this application.
- Aligns with SDR-07 from Phase 1 requirements.

### 3.3 Suppression Policy

Findings that cannot be fixed (e.g., transitive dependencies pinned by the Spring Boot BOM) are suppressed in `owasp-suppressions.xml`. Each suppression entry requires:
- The exact CVE identifier
- A written justification explaining why the attack vector is not reachable
- A reviewer name and review date
- An annual review obligation

Suppressions must never be used to hide exploitable vulnerabilities — only to acknowledge known limitations with documented rationale.

### 3.4 NVD Database Caching

The NVD database is several hundred megabytes. The pipeline uses a weekly GitHub Actions cache keyed on `year-weeknumber` to avoid downloading it on every run. The `NVD_API_KEY` secret eliminates NVD rate-limiting on unauthenticated requests.

### 3.5 Report Artifact

The HTML report is uploaded as a GitHub Actions artifact retained for 30 days with `if: always()`, so the team can review which dependency caused a failure before fixing it.

---

## 4. Static Application Security Testing (SAST) — SonarCloud

### 4.1 Tool Choice

**SonarCloud** (free tier for public repositories).

GitHub's built-in CodeQL already runs automatically on every push via the repository's default code scanning setup and results appear in the **Security > Code scanning** tab. Adding a duplicate CodeQL job in the workflow would run the analysis twice for no benefit.

SonarCloud is added as a complementary SAST layer because it provides:
- Code quality metrics (code smells, maintainability, duplication) in addition to security rules
- JaCoCo coverage integration — coverage data from the test run is uploaded alongside the analysis
- A dedicated project dashboard accessible to the whole team and evaluator at sonarcloud.io

### 4.2 Coverage Integration

The `sonar` job runs `mvn verify` before the analysis, which executes all tests and generates the JaCoCo XML report. SonarCloud picks up this report automatically and displays per-file coverage on the dashboard.

### 4.3 Quality Gate — Known Limitation

SonarCloud's default quality gate ("Sonar way") requires ≥ 80% coverage on new code. The current test suite does not meet this threshold. As a result:

- The quality gate **fails** in the SonarCloud dashboard.
- The pipeline job **passes** because `-Dsonar.qualitygate.wait=true` is not set.

**Why this is intentional for Sprint 2:** Adding `-Dsonar.qualitygate.wait=true` would make the pipeline correctly fail on quality gate violations. However, doing so without first creating a custom quality gate that removes or lowers the coverage condition would permanently break the pipeline until coverage reaches 80%. A custom quality gate requires defining acceptable thresholds for this project's maturity level.

**Planned fix:** In a future sprint, create a custom SonarCloud quality gate (Organization → Quality Gates) that gates on security issues and bugs but uses a lower coverage threshold (e.g., 60%). Then add `-Dsonar.qualitygate.wait=true` to enforce it in the pipeline.

---

## 5. Container Security Scan — Trivy

### 5.1 Why Trivy in Addition to OWASP DC

OWASP DC scans Maven JARs (the Java dependency layer). It cannot see OS-level packages inside the Docker image. The runtime image (`eclipse-temurin:21-jre-alpine`) ships Alpine Linux packages (`musl`, `openssl`, `busybox`, etc.) that may carry their own CVEs.

Trivy fills this gap by scanning the built Docker image, giving complete CVE coverage across both layers.

### 5.2 Configuration Choices

| Setting | Value | Rationale |
|---|---|---|
| `severity` | `CRITICAL,HIGH` | Matches the OWASP DC threshold (CVSS ≥ 7.0 = HIGH+) for consistent policy |
| `ignore-unfixed` | `true` | Only fails on CVEs that have a released fix — mirrors the OWASP DC suppression policy of not blocking on issues we cannot resolve |
| `exit-code` | `1` | Fails the pipeline job, blocking the merge |

### 5.3 No Suppression File

Unlike OWASP DC, Trivy does not use a suppression file. The `ignore-unfixed: true` flag achieves the same outcome — unfixable CVEs in the base image are silently skipped. When a CVE has a fix, upgrading the base image tag in the `Dockerfile` is the correct resolution.

---

## 6. Branch Protection Rules

Branch protection is configured manually in GitHub (Repository → Settings → Branches → `main`):

| Setting | Value |
|---|---|
| Require a pull request before merging | Enabled |
| Required approving reviews | 1 |
| Dismiss stale PR approvals when new commits are pushed | Enabled |
| Require status checks to pass before merging | Enabled |
| Required status checks | `Build & Test`, `SCA — OWASP Dependency-Check`, `SAST — SonarCloud`, `Container Scan — Trivy` |
| Require branches to be up to date before merging | Enabled |
| Do not allow bypassing the above settings | Enabled |

**Why 1 reviewer:** The team has 4 developers on a strict sprint timeline. 1 approval ensures a second pair of eyes without serializing work.

---

## 7. Activation Checklist

- [x] **Add GitHub secret `NVD_API_KEY`:** Done.
- [x] **Add GitHub secret `SONAR_TOKEN`:** Done.
- [x] **Configure SonarCloud project:** Done. Main branch set to `main`.
- [x] **Configure branch protection:** Done. `main` branch protected with required status checks.

---

## 8. Trade-offs and Known Limitations

| Item | Trade-off |
|---|---|
| OWASP DC CVSS threshold 7.0 | Medium CVEs (4.0–6.9) do not block the build. A future sprint could tighten this to 6.0. |
| SonarCloud quality gate not enforced | `-Dsonar.qualitygate.wait=true` is not set because the default gate requires 80% coverage which the current test suite does not reach. Fix: create a custom quality gate with an appropriate threshold, then enable the flag. |
| SonarCloud free tier — main branch only | PR-level analysis (decorated inline comments on pull requests) is a paid SonarCloud feature. Only the `main` branch is analysed on the free tier. |
| NVD cache refresh weekly | New CVEs published mid-week are not picked up until the cache expires. Critical zero-days require manually invalidating the cache. |
| No DAST in pipeline | OWASP ZAP DAST was planned in Phase 1 (ST-01, ST-03, ST-06). It requires a running application instance and is deferred to a sprint where a staging environment exists. |
| Trivy — base image CVEs only | Trivy scans the OS layer in the Docker image. `ignore-unfixed: true` means unfixable Alpine CVEs are not blocking. When a fix is released, updating the base image tag in the `Dockerfile` resolves it. |
