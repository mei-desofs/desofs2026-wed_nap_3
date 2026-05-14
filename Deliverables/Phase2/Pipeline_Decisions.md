# Pipeline Architecture — Decision Record

**Developer 1 — The Pipeline Architect**
**Phase 2, Sprint 1 | DESOFS 2026**

---

## 1. Scope

This document records the technical decisions made when designing the CI/CD pipeline for EnderChest. It covers job structure, tool selection, threshold choices, and configuration rationale so that the decisions can be evaluated and revisited.

Files created/modified in this sprint:

| File | Purpose |
|---|---|
| `.github/workflows/ci.yml` | The pipeline definition |
| `pom.xml` | Added OWASP DC and JaCoCo Maven plugins |

---

## 2. Pipeline Structure

### 2.1 Job Dependency Graph

```
push / pull_request
        │
        ▼
 build-and-test          ← must pass before anything else runs
   │           │
   ▼           ▼
  sca         sast       ← run in parallel to keep pipeline fast
(OWASP DC)  (CodeQL)
```

**Rationale:** Running SCA and SAST in parallel saves wall-clock time. Both are gated behind `build-and-test` because analyzing code that doesn't compile is wasteful, and a failing test suite should block the pipeline entirely before expensive security scans run.

### 2.2 Trigger Strategy

The pipeline triggers on **every push and every pull request** regardless of branch. This enforces security gates from the very first commit on any feature branch, not just at PR time. The cost is a marginally higher Action-minute usage, which is acceptable for the security guarantee it provides.

### 2.3 PostgreSQL Service Container

`build-and-test` includes a PostgreSQL 16 service container. There are currently no tests, so the database is not exercised yet. It is included now so that when Developers 2, 3, and 4 add `@SpringBootTest` integration tests, the pipeline does not break. The datasource URL is injected via environment variables that override `application.properties`.

The JWT JWK set URI is overridden with a local placeholder in CI. Tests that use `@WithMockUser` do not trigger JWT validation, so this placeholder is never actually contacted. This avoids a hard dependency on a live IdP in the pipeline.

The `sast` job (CodeQL) does not need a service container — it only compiles source code, it does not run the application.

---

## 3. Software Composition Analysis (SCA)

### 3.1 Tool Choice: OWASP Dependency-Check

**Chosen over:** Snyk (Phase 1 plan mentioned both).

**Reason:** OWASP Dependency-Check is open source, requires no external SaaS account, and integrates directly with Maven via a plugin. Its vulnerability database is sourced from the authoritative NVD (National Vulnerability Database), making its findings directly reportable using CVSS scores. Snyk provides a better developer experience (inline PR comments) but requires a team account and a billing decision. OWASP DC can be upgraded to Snyk later if the team decides to.

### 3.2 CVSS Threshold: 7.0

The `failBuildOnCVSS=7` configuration rejects any dependency with a CVSS v3 base score of 7.0 or higher.

**Rationale:**
- CVSS 7.0 is the boundary between **Medium** (4.0–6.9) and **High** (7.0–8.9) severity.
- All CRITICAL (9.0–10.0) and HIGH vulnerabilities are blocked.
- Medium vulnerabilities are reported but do not block — a compromise between security rigor and practicality, since many Medium findings are context-dependent (e.g., a vulnerability only exploitable via a feature we don't use).
- This aligns with SDR-07 from Phase 1 requirements.

**Suppression file:** An `owasp-suppressions.xml` file is referenced in `pom.xml` (does not need to exist on disk until a false positive needs suppression). When a finding is a confirmed false positive, it must be suppressed there with a written justification — not by lowering the threshold.

### 3.3 NVD Database Caching

The NVD database is several hundred megabytes. Without caching, every CI run downloads the full database, which can take 5–30 minutes using the legacy feed. The pipeline uses a weekly GitHub Actions cache keyed on `year-weeknumber`. This means:
- Runs within the same week reuse the cached database (fast).
- The cache refreshes each week to pick up new CVEs.

**NVD API Key (`NVD_API_KEY` secret):** The NVD now rate-limits unauthenticated requests severely. Registering for a free API key at https://nvd.nist.gov/developers/request-an-api-key eliminates this bottleneck. The key is passed as `-DnvdApiKey=` and if the secret is not set, the plugin falls back to the unauthenticated feed (slower but functional).

**Action:** Register for an NVD API key and add it as a GitHub Actions secret named `NVD_API_KEY`.

### 3.4 Report Artifact

The HTML report (`target/dependency-check-report.html`) is uploaded as a GitHub Actions artifact retained for 30 days. The `if: always()` condition ensures the report is uploaded even when the build fails — this allows the team to review *which* dependency caused the failure before fixing it.

---

## 4. Static Application Security Testing (SAST)

### 4.1 Tool Choice: GitHub CodeQL

**Chosen over:** SonarCloud, self-hosted SonarQube.

**Reason:** The project evaluator (Prof. NAP) has administrator access to this GitHub repository. CodeQL results appear directly in the repository's **Security > Code scanning** tab — the evaluator can review findings without needing to log into any external service. SonarCloud would require a separate account and site visit to see results.

Additional advantages:
- Zero external accounts or secrets required (`GITHUB_TOKEN` is provided automatically by GitHub Actions)
- Free for both public and private repositories
- Results are mapped directly to CWEs, which aligns with the STRIDE/threat model language used in Phase 1
- Industry standard tool: used by Microsoft, Google, and the Linux kernel project
- No configuration files beyond the workflow itself

### 4.2 Query Suite: `security-extended`

The workflow uses `queries: security-extended`, which is a superset of the standard `security-and-quality` suite. It includes:
- All OWASP Top 10 checks for Java
- CWE-mapped vulnerability patterns (injection, path traversal, XXE, deserialization, etc.)
- Experimental security queries not yet in the stable suite

For a security engineering project, `security-extended` is more appropriate than the default because it prioritises finding vulnerabilities over code quality metrics.

### 4.3 PR Blocking

CodeQL blocks PRs via GitHub's native branch protection status checks — the same mechanism used for `Build & Test` and `SCA`. No Quality Gate configuration on an external site is needed. Configure it under:

> Repository > Settings > Branches > main > Require status checks > `SAST - GitHub CodeQL`

### 4.4 Build Step

CodeQL intercepts the normal compiler output to build its semantic model of the code. The workflow uses `mvn -B clean compile` (main sources only). This is faster than `mvn verify` and sufficient for CodeQL — it does not execute the application, so no PostgreSQL service container is needed in the SAST job.

### 4.5 JaCoCo Code Coverage

The `jacoco-maven-plugin` is in `pom.xml` to generate coverage reports (`target/site/jacoco/`) when tests are added by Developers 2 and 3. It is not consumed by CodeQL but provides the team with visibility into test coverage as CI artifacts.

---

## 5. Branch Protection Rules

Branch protection cannot be configured via code — it must be done manually on GitHub. These are the rules that must be set on the `main` branch:

**Navigate to:** Repository > Settings > Branches > Add rule > Branch name pattern: `main`

| Setting | Value |
|---|---|
| Require a pull request before merging | Enabled |
| Required approving reviews | 1 |
| Dismiss stale PR approvals when new commits are pushed | Enabled |
| Require status checks to pass before merging | Enabled |
| Required status checks | `Build & Test`, `SCA - OWASP Dependency-Check`, `SAST - GitHub CodeQL` |
| Require branches to be up to date before merging | Enabled |
| Do not allow bypassing the above settings | Enabled |

**Why 1 reviewer and not 2:** The team has 4 developers and a strict sprint timeline. Requiring 2 reviewers on a team this size would serialize work unnecessarily. 1 approval ensures a second pair of eyes without creating a bottleneck.

---

## 6. Activation Checklist

- [x] **Add GitHub secret `NVD_API_KEY`:** Done.
- [x] **Enable Code Scanning / CodeQL on GitHub:** Done. Findings visible in Security tab.
- [x] **Configure branch protection:** Done. `main` branch protected with required status checks.

All pipeline steps are fully operational.

---

## 7. Trade-offs and Known Limitations

| Item | Trade-off |
|---|---|
| OWASP DC CVSS threshold 7.0 | Medium CVEs (4.0-6.9) are not build-blockers. They appear in the report but do not fail the pipeline. This may allow low-severity vulnerable dependencies to linger. A future sprint could tighten this to 6.0. |
| CodeQL vs SonarCloud | CodeQL focuses purely on security vulnerabilities. SonarCloud additionally provides code smell and maintainability metrics. For this security-engineering course, security coverage takes priority over maintainability metrics. |
| NVD cache refresh weekly | New CVEs published mid-week are not picked up until the next cache miss. Critical zero-days would require manually invalidating the cache. |
| No DAST in pipeline | OWASP ZAP DAST was planned in Phase 1 (ST-01, ST-03, ST-06). It requires a running application instance and is deferred to a later sprint where a staging environment exists. |
| Coverage not enforced | JaCoCo is configured but no coverage threshold is enforced yet. This will be addressed in Sprint 2 when test suites from Developers 2 and 3 exist. |
