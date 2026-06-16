# Pipeline Architecture — Decision Record

**Developer 1 — The Pipeline Architect**
**Phase 2, Sprint 1 | DESOFS 2026**

---

## 1. Scope

This document records the technical decisions made when designing and implementing the CI/CD pipeline for EnderChest. It covers job structure, tool selection, threshold choices, and configuration rationale so that the decisions can be evaluated and revisited in future sprints.

Files created or modified as part of this work:

| File | Purpose |
|---|---|
| `.github/workflows/ci.yml` | The pipeline definition |
| `.github/actions/helm-validate/` | Composite action: Helm lint + kubeconform validation |
| `.gitleaks.toml` | Gitleaks ruleset extension and false-positive allowlist |
| `pom.xml` | OWASP DC, JaCoCo, and SonarCloud Maven configuration |
| `owasp-suppressions.xml` | Documented false-positive suppressions for OWASP DC |

---

## 2. Pipeline Structure

### 2.1 Job Dependency Graph

```mermaid
flowchart TD
    trigger([Push / Pull Request to main])
    trigger --> build
    trigger --> secret

    secret["Secret Scanning\nGitleaks\nFails on detected secrets"]
    build["Build & Test\nmvn clean install\nH2 in-memory DB · JaCoCo coverage"]

    build --> sca
    build --> sonar
    build --> trivy
    build --> helm
    build --> dast

    sca["SCA\nOWASP Dependency-Check\nFails on CVSS ≥ 7.0"]
    sonar["SAST\nSonarCloud\nQuality gate enforced"]
    trivy["Container Scan\nTrivy\nFails on HIGH/CRITICAL CVEs\nwith a known fix available"]
    helm["Helm Validate\nlint + kubeconform"]
    dast["DAST\nOWASP ZAP\nRuntime scan vs OpenAPI"]

    sca --> report[/"OWASP HTML Report\nArtifact · 30 days"/]
    dast --> zapreport[/"ZAP HTML Report\nArtifact · 30 days"/]

    sca --> deploy
    sonar --> deploy
    trivy --> deploy
    helm --> deploy
    dast --> deploy
    deploy["Deploy\nHelm → K3s\nmain branch · push only"]
```

The pipeline is organised into three tiers. **Secret Scanning** runs independently of the build so leaked credentials are caught even when the code does not compile. **Build & Test** is the gate for the security-analysis tier: SCA, SAST, Container Scan, Helm Validate, and DAST all run in parallel once it passes, which keeps total pipeline time low while ensuring no scan runs against code that does not compile or has failing tests. Finally, **Deploy** runs only on a push to `main` after every check has passed.

Secret Scanning, Helm Validate, and DAST were not all present from the first iteration — DAST and Helm Validate were added once the application could be booted in CI and a Helm chart existed (see §7 and §8). The remainder of this document records the rationale behind each job.

### 2.2 Triggers

The pipeline triggers on every push and every pull request targeting `main`. This enforces all security gates at PR time, before any code reaches the main branch.

### 2.3 Test Database

Tests use an H2 in-memory database configured in `src/test/resources/application-test.properties`, so no PostgreSQL service container is needed in CI. The JWT JWK set URI is overridden with a local placeholder — tests using `@WithMockUser` never contact the Auth0 IdP, keeping the pipeline free of external runtime dependencies.

---

## 3. Software Composition Analysis (SCA) — OWASP Dependency-Check

### 3.1 What It Does

OWASP Dependency-Check (OWASP DC) scans every JAR in the project and cross-references each one against the **NVD (National Vulnerability Database)** — the US government's (NIST) authoritative public database of known software vulnerabilities. Each entry in the NVD carries a **CVSS score** (Common Vulnerability Scoring System, 0–10) that rates severity. If a dependency matches a known CVE with a score above the configured threshold, the build fails.

### 3.2 Why OWASP DC Over Snyk

Snyk was considered as an alternative. OWASP DC was chosen because it is open source, requires no external SaaS account, and integrates directly with Maven. Snyk provides a better developer experience (inline PR comments) but requires a team account and a billing decision. OWASP DC can be replaced with Snyk in a future sprint if the team decides to.

### 3.3 CVSS Threshold: 7.0

`failBuildOnCVSS=7` was set to reject any dependency with a CVSS v3 base score of 7.0 or higher.

- CVSS 7.0 is the boundary between **Medium** (4.0–6.9) and **High** (7.0–8.9).
- All CRITICAL (9.0–10.0) and HIGH vulnerabilities block the build.
- Medium findings are reported but do not block — many are context-dependent and not exploitable in this application.
- This threshold aligns with SDR-07 from the Phase 1 requirements.

### 3.4 Suppression Policy

Some findings cannot be fixed because the vulnerable dependency is managed by the Spring Boot BOM and cannot be upgraded independently of Spring Boot itself. These are suppressed in `owasp-suppressions.xml` rather than by lowering the threshold.

Each suppression entry includes the exact CVE identifier, a written justification explaining why the attack vector is not reachable in EnderChest, a reviewer name and review date, and an annual review obligation. This ensures suppressions are deliberate and auditable rather than silent workarounds.

### 3.5 NVD Database Caching and API Key

Before OWASP DC can scan anything, it must download the entire NVD database to the CI runner — this is how it knows which CVEs exist. The database is several hundred megabytes.

Without an API key, NVD rate-limits unauthenticated requests to approximately one request every six seconds. At that rate, the full database download can take 30+ minutes per run or time out entirely. A free NVD API key was registered and stored as a GitHub Actions secret (`NVD_API_KEY`), which removes the throttle and brings the download down to a few minutes.

Additionally, a weekly GitHub Actions cache keyed on `year-weeknumber` was introduced so that runs within the same week reuse the already-downloaded database entirely, skipping the download step for most runs.

### 3.6 Report Artifact

The HTML report is uploaded as a GitHub Actions artifact retained for 30 days with `if: always()`, so the team can review which dependency caused a failure even when the build is red.

---

## 4. Static Application Security Testing (SAST) — SonarQube Cloud

### 4.1 Why SonarCloud in Addition to GitHub CodeQL

GitHub's built-in CodeQL runs automatically on every push via the repository's default code scanning setup and results appear in the **Security > Code scanning** tab. Running a duplicate CodeQL job in the workflow would analyse the same code twice for no benefit, so the explicit CodeQL workflow job was removed.

SonarCloud was added as a complementary SAST layer because it provides:
- Code quality metrics (code smells, maintainability, duplication) alongside security rules
- JaCoCo coverage integration — coverage data from the test run is uploaded with the analysis and displayed per file on the dashboard
- A dedicated project dashboard accessible to the whole team and evaluator at sonarcloud.io

### 4.2 Coverage Integration

The `sonar` job runs `mvn verify` before the analysis, which executes all tests and generates the JaCoCo XML report. SonarCloud picks this up automatically and shows per-file coverage on the project dashboard.

### 4.3 Quality Gate

SonarCloud's default quality gate ("Sonar way") requires ≥ 80% coverage on new code. In Sprint 1 the `-Dsonar.qualitygate.wait=true` flag was intentionally left unset so a failing gate would not block the build while coverage was still low.

> [!NOTE]
> In Sprint 2 the flag was enabled in the `sonar` job, so the pipeline now waits on and enforces the SonarCloud quality gate. Coverage was raised with new service-layer tests (Folder, User, AccessShare) to support this. See [Sprint2/README.md §3.2](./Sprint2/README.md#32-test-coverage--quality-gate).

---

## 5. Container Security Scan — Trivy

### 5.1 Why Trivy in Addition to OWASP DC

OWASP DC scans Maven JARs (the Java dependency layer). It cannot see OS-level packages inside the Docker image. The runtime image (`eclipse-temurin:21-jre-alpine`) ships Alpine Linux packages (`musl`, `openssl`, `busybox`, etc.) that may carry their own CVEs. Trivy fills this gap by scanning the built Docker image, providing complete CVE coverage across both the OS layer and the Java layer.

### 5.2 Configuration Choices

| Setting | Value | Rationale |
|---|---|---|
| `severity` | `CRITICAL,HIGH` | Matches the OWASP DC threshold (CVSS ≥ 7.0 = HIGH+) for a consistent policy across both tools |
| `ignore-unfixed` | `true` | Only fails on CVEs that have a released fix — mirrors the OWASP DC suppression policy of not blocking on issues that cannot be resolved |
| `exit-code` | `1` | Fails the pipeline job, blocking the merge |

When a HIGH/CRITICAL CVE with a fix is found in the base image, the resolution is to update the base image tag in the `Dockerfile` to a version that includes the fix. No separate suppression file is needed because `ignore-unfixed: true` already handles unfixable findings.

---

## 6. Secret Scanning — Gitleaks

### 6.1 What It Does

The `secret-scan` job runs **Gitleaks** (`gitleaks/gitleaks-action@v2`) on every push and pull request. Gitleaks scans the repository — including git history — for committed credentials such as API keys, tokens, and private keys, and fails the build when a secret is detected. Unlike the other security jobs it does **not** depend on `build-and-test`, so leaked credentials are caught even when the code does not compile.

### 6.2 False-Positive Allowlist

A repository-level `.gitleaks.toml` extends the default ruleset (`useDefault = true`) and allowlists known-public identifiers that are not secrets — notably the SonarCloud project key (`mei-desofs-wed-nap-3_...`), which is a public reference and not a credential. Genuine secrets such as `SONAR_TOKEN`, `NVD_API_KEY`, and `GITLEAKS_LICENSE` are stored as GitHub Actions secrets and never appear in source.

---

## 7. Helm Chart Validation — kubeconform

### 7.1 What It Does

The `helm-validate` job runs a composite action (`.github/actions/helm-validate`) that lints the Helm chart and renders its templates, then validates the resulting Kubernetes manifests against the upstream JSON schemas with **kubeconform**. This catches malformed manifests, invalid field types, and unsupported API versions before they can be deployed.

### 7.2 CRD Skips

K3s-specific custom resources that are not part of the upstream Kubernetes schema set — `Middleware` (Traefik) and `HelmChartConfig` (K3s Traefik configuration) — are passed to kubeconform with `-skip` so that valid cluster-native resources do not fail validation.

---

## 8. Dynamic Application Security Testing (DAST) — OWASP ZAP

### 8.1 Why DAST in Addition to SAST

SAST (SonarCloud) and SCA (OWASP DC) analyse source code and dependencies statically — they never run the application. DAST exercises the **running** application over HTTP, catching issues only observable at runtime: missing security headers, error-handling leaks, and authentication enforcement on real endpoints. DAST (OWASP ZAP) was planned in Phase 1 (ST-01, ST-03, ST-06) but required a bootable application instance in CI, which is why it was introduced once that was in place.

### 8.2 How It Runs

The `dast` job stands up a realistic runtime environment and scans it:

- A **PostgreSQL 16** service container provides a real database (not H2), so the app runs as it would in production.
- The application JAR is built and started against that database, with the JWT JWK set URI pointed at a local placeholder so no external IdP is contacted.
- The job polls `/v3/api-docs` until the application is ready.
- **OWASP ZAP** (`ghcr.io/zaproxy/zaproxy:stable`, `zap-api-scan.py`) scans the application using its OpenAPI specification as the target surface.
- The ZAP HTML report is uploaded as an artifact (`zap-dast-report`, 30-day retention) with `if: always()`.

### 8.3 Report-Only Mode

The scan runs with the `-I` flag, which reports findings without failing the build. This avoids blocking the pipeline on informational and low-severity ZAP alerts while the baseline is established; a ZAP alert filter can later promote selected rules to build-failing once the expected findings have been triaged.

---

## 9. Branch Protection Rules

Branch protection was configured on the `main` branch in GitHub to enforce that all pipeline jobs pass before a pull request can be merged:

| Setting | Value |
|---|---|
| Require a pull request before merging | Enabled |
| Required approving reviews | 1 |
| Dismiss stale PR approvals when new commits are pushed | Enabled |
| Require status checks to pass before merging | Enabled |
| Required status checks | `Build & Test`, `Secret Scanning — Gitleaks`, `SCA — OWASP Dependency-Check`, `SAST — SonarCloud`, `Container Scan — Trivy`, `Helm Validate`, `DAST — OWASP ZAP` |
| Require branches to be up to date before merging | Enabled |
| Do not allow bypassing the above settings | Enabled |

One required reviewer was chosen over two because the team has 4 developers on a strict sprint timeline. Requiring 2 reviewers would serialize work unnecessarily; 1 approval ensures a second pair of eyes without creating a bottleneck.

---

## 10. Trade-offs and Known Limitations

| Item | Trade-off |
|---|---|
| OWASP DC CVSS threshold 7.0 | Medium CVEs (4.0–6.9) do not block the build. A future sprint could tighten this to 6.0. |
| SonarCloud quality gate | Enforced in Sprint 2 via `-Dsonar.qualitygate.wait=true`. A custom gate threshold appropriate to the project's coverage was used so the pipeline fails on real regressions rather than the default 80% rule. |
| SonarCloud free tier — main branch only | PR-level analysis (inline comments on pull requests) is a paid SonarCloud feature. Only the `main` branch is analysed on the free tier. |
| NVD cache refresh weekly | New CVEs published mid-week are not picked up until the cache expires. Critical zero-days would require manually invalidating the cache. |
| DAST runs report-only | The ZAP scan uses `-I`, so findings are reported as an artifact but do not fail the build. Tightening requires a ZAP alert filter to separate expected from actionable findings (see §8.3). |
| Trivy — base image CVEs only | Trivy scans the OS layer in the Docker image. `ignore-unfixed: true` means unfixable Alpine CVEs are not blocking. When a fix is released, updating the base image tag in the `Dockerfile` resolves it. |
