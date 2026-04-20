# Security Testing Plan — Secure File Management System

**DESOFS — Desenvolvimento de Software Seguro | 2025/2026**  
**Phase 1 — Security Testing Plan**  
**Date:** April 2026 | Instituto Superior de Engenharia do Porto (ISEP)

---

## 1. Introduction

This document presents the Security Testing Plan for Phase 1 of the DESOFS project — Secure File Management System. It covers three complementary areas:

- **Security Test Plan** — 10 test cases with steps, expected results and tools, grounded in risk-based testing methodology and aligned with course practices (SAST, DAST, Fuzzing, Penetration Testing).
- **Traceability Matrix** — bidirectional traceability between abuse cases (Element 3), security requirements (RS-XX) and ASVS 5.0 references, ensuring each control has at least one associated test.
- **ASVS Checklist** — verification of OWASP Application Security Verification Standard (v5.0) controls relevant to the system architecture, at design level (Phase 1).

### 1.1 Context: Secure Software Development Lifecycle (SSDLC)

In accordance with SSDLC best practices, security test planning should occur during the design phase, before implementation. This approach — known as **shift-left security** — allows security issues to be identified and corrected in the early stages.

Tests defined in this document are organised into two time horizons:

- **Pre-code (design)** — tests that can be validated by architecture review, static configuration analysis or documentation review, without requiring implemented code.
- **Phase 2** — tests that require executable code and will be executed in the Build & Test and Go to Production phases of the DevSecOps pipeline.

### 1.2 Tools and Reference Methodologies

| Type | Tools | Purpose |
|------|-------|---------|
| SAST | SonarQube, Snyk Code | Source code analysis without execution |
| DAST | OWASP ZAP, Burp Suite | Tests on running application (black-box) |
| SCA | Snyk, OWASP Dependency-Check | Third-party dependency analysis |
| Fuzzing | OWASP ZAP Active Scan, FuzzDB | Malformed / unexpected input injection |
| Penetration Testing | Burp Suite, Postman, curl | Directed attack simulation |

> **Note:** Test cases in this phase are defined at plan level (design-time). Effective execution will occur in Phase 2, when code is available. Tests marked as *Pre-code (design)* can be validated by architecture review.

---

## 2. Security Test Plan

### 2.1 Methodology

The adopted methodology is **risk-based testing**, aligned with the DevSecOps pipeline. Tests are prioritised by the DREAD score defined by Element 3 and cover four complementary testing types:

- **SAST** — source code analysis using SonarQube and Snyk before compilation.
- **DAST** — tests on the running application (black-box) using OWASP ZAP and Burp Suite.
- **Manual Penetration Testing** — directed tests using Burp Suite, Postman and curl.
- **Security Code Review** — manual and SAST-assisted review focused on critical controls.

Each test case includes: unique identifier (ST-XX), descriptive name, detailed execution steps, expected result (pass/fail criterion), recommended tool and execution phase.

### 2.2 Test Cases

> 🔴 **Red = Critical Priority (DREAD ≥ 2.4)** | 🟡 **Yellow = Medium Priority (DREAD 1.8–2.3)**

---

#### ST-01 — Path Traversal in File Paths 🔴

| Field | Details |
|-------|---------|
| **Abuse Case** | AC-01 |
| **Requirements** | RS-03, RS-04 |
| **ASVS Ref.** | V12.3.1, V5.1.3 |
| **Method** | DAST + Manual |
| **Tool** | OWASP ZAP / curl / FuzzDB |
| **Phase** | Phase 2 (integration) |

**Steps:**
1. Send request with `filename=../../etc/passwd` to the upload and download endpoint.
2. Repeat with variations: URL encoding (`%2e%2e%2f`), double encoding, null byte injection.
3. Test against all endpoints that accept filename/path parameters.
4. Use FuzzDB path traversal wordlist with OWASP ZAP Active Scan.

**Expected Result:** HTTP 400 returned; no file outside the base directory is accessed; audit log records the attempt.

---

#### ST-02 — IDOR on File Download Endpoint 🔴

| Field | Details |
|-------|---------|
| **Abuse Case** | AC-02 |
| **Requirements** | RS-01, RS-02 |
| **ASVS Ref.** | V8.3.4, V4.2.1 |
| **Method** | Manual + Automated |
| **Tool** | Burp Suite Intruder / Python Script |
| **Phase** | Phase 2 (unit test + integration) |

**Steps:**
1. Authenticate as Viewer with access to file ID=42.
2. Iteratively enumerate GET `/files/1` through GET `/files/100` using Burp Suite Intruder.
3. Verify responses for files not shared with the Viewer.
4. Repeat as Editor, attempting to access files from other users.

**Expected Result:** HTTP 403 Forbidden for all files not shared with the Viewer. No other users' data is accessible.

---

#### ST-03 — Malicious File Upload (RCE Attempt) 🔴

| Field | Details |
|-------|---------|
| **Abuse Case** | AC-03 |
| **Requirements** | RS-03, RS-05 |
| **ASVS Ref.** | V12.2.1, V5.1.3 |
| **Method** | Manual |
| **Tool** | Burp Suite / curl |
| **Phase** | Phase 2 (integration) |

**Steps:**
1. Create file `shell.php` with code `<?php system($_GET['cmd']); ?>`.
2. Upload with `Content-Type: image/jpeg` (MIME spoofing).
3. Attempt upload of `.php`, `.jsp`, `.exe`, `.sh` files.
4. Attempt double extension: `shell.php.jpg`.
5. Verify if the uploaded file is executable via HTTP.

**Expected Result:** HTTP 415 or 400; upload rejected based on real magic bytes; file not stored; file path is not accessible via HTTP.

---

#### ST-04 — Brute Force on Authentication Endpoint 🔴

| Field | Details |
|-------|---------|
| **Abuse Case** | AC-04 |
| **Requirements** | RS-01, RS-06, RS-10 |
| **ASVS Ref.** | V2.2.1, V2.2.4 |
| **Method** | Automated |
| **Tool** | Hydra / OWASP ZAP |
| **Phase** | Phase 2 (integration) |

**Steps:**
1. Run Hydra with a list of 1000 common passwords against `/auth/login`.
2. Monitor responses after 5, 10, and 20 attempts.
3. Verify whether the account is blocked or if a rate limit is applied.
4. Check if the block persists after the lockout period.

**Expected Result:** Account locked or HTTP 429 Too Many Requests after 5–10 failed attempts. Response time increases progressively (exponential backoff).

---

#### ST-05 — JWT Token Replay After Logout / Expiry 🟡

| Field | Details |
|-------|---------|
| **Abuse Case** | AC-05 |
| **Requirements** | RS-01, RS-09 |
| **ASVS Ref.** | V3.5.2, V3.2.1 |
| **Method** | Manual |
| **Tool** | Postman / Burp Suite |
| **Phase** | Phase 2 (unit test) |

**Steps:**
1. Authenticate and capture the JWT in the Authorization header.
2. Perform explicit logout.
3. Reuse the captured JWT in a new authenticated request.
4. Wait for token expiry (e.g., 30 minutes) and reuse again.

**Expected Result:** HTTP 401 Unauthorized after logout. HTTP 401 after token expiry. Token revoked in server blocklist.

---

#### ST-06 — DoS via Massive File Upload 🔴

| Field | Details |
|-------|---------|
| **Abuse Case** | AC-06 |
| **Requirements** | RS-05, RS-10 |
| **ASVS Ref.** | V12.2.3, V5.1.3 |
| **Method** | Automated |
| **Tool** | Python Script / Locust |
| **Phase** | Phase 2 (load test) |

**Steps:**
1. Run Python script with 50 threads making simultaneous uploads of maximum size files.
2. Attempt to upload files exceeding the maximum limit (e.g., 500MB).
3. Monitor system performance during the test.
4. Verify quota enforcement per user.

**Expected Result:** Uploads above the size limit rejected (HTTP 413). Per-user quota applied. System remains available during the test (no crash).

---

#### ST-07 — Unauthorised Deletion by Editor Role 🟡

| Field | Details |
|-------|---------|
| **Abuse Case** | AC-07 |
| **Requirements** | RS-02 |
| **ASVS Ref.** | V4.2.2, V8.2.1 |
| **Method** | Manual |
| **Tool** | Postman / Burp Suite |
| **Phase** | Phase 2 (integration) |

**Steps:**
1. Authenticate as Editor in a shared folder.
2. Send `DELETE /files/{id}` for critical files.
3. Attempt to delete files from other users.
4. Check audit log for recorded attempt.

**Expected Result:** HTTP 403 Forbidden. File not deleted. Attempt recorded in audit log.

---

#### ST-08 — User Enumeration via Error Messages 🔴

| Field | Details |
|-------|---------|
| **Abuse Case** | AC-08 |
| **Requirements** | RS-03, RS-09 |
| **ASVS Ref.** | V2.2.5, V7.4.1 |
| **Method** | Manual + Automated |
| **Tool** | Burp Suite Comparer / curl |
| **Phase** | Phase 2 (integration) |

**Steps:**
1. Send login requests with a non-existent email and a registered email.
2. Compare response body, HTTP code and response time.
3. Use Burp Suite Comparer to detect subtle differences.

**Expected Result:** Identical response (body, HTTP code, timing) for existing and non-existing email. No information that allows distinguishing the two cases.

---

#### ST-09 — HTTPS Enforcement and Security Headers 🟡

| Field | Details |
|-------|---------|
| **Abuse Case** | AC-05 |
| **Requirements** | RS-09, RNF-01 |
| **ASVS Ref.** | V9.1.1, V14.4.3 |
| **Method** | Manual |
| **Tool** | curl / Mozilla Observatory |
| **Phase** | Phase 2 (integration) |

**Steps:**
1. Send HTTP (non-HTTPS) request and verify redirect.
2. Verify presence of `Strict-Transport-Security` header.
3. Verify headers `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`.

**Expected Result:** HTTP redirects to HTTPS (301). HSTS with `max-age >= 31536000` present. CSP and `X-Content-Type-Options` present and configured.

---

#### ST-10 — Password Hash Algorithm Verification 🔴

| Field | Details |
|-------|---------|
| **Abuse Case** | AC-04 |
| **Requirements** | RS-06 |
| **ASVS Ref.** | V2.4.1, V2.4.2 |
| **Method** | SAST + Code Review |
| **Tool** | SonarQube / Snyk (SAST) + Manual Review |
| **Phase** | Phase 2 (code review) |

**Steps:**
1. Code review of the registration and authentication module.
2. Verify if BCrypt or Argon2 are used with work factor ≥ 10.
3. Confirm absence of MD5, SHA-1 or SHA-256 without salt for passwords.
4. Run SonarQube / Snyk to detect use of weak algorithms.

**Expected Result:** BCrypt (cost ≥ 10) or Argon2id used. Absence of MD5/SHA-1. Unique salt per user. Confirmed by SAST (SonarQube/Snyk).

---

## 3. Traceability Matrix

The traceability matrix links each test case to the abuse case that motivated it (Element 3), the corresponding security requirements (RS-XX) and the applicable ASVS 5.0 reference.

> 🔴 **Critical (DREAD ≥ 2.4)** | 🟡 **Medium (DREAD 1.8–2.3)**

| Test ID | Test Case | Abuse Case | Requirements | ASVS Ref. | Method | Priority |
|---------|-----------|------------|--------------|-----------|--------|----------|
| ST-01 | Path Traversal | AC-01 | RS-03, RS-04 | V12.3.1, V5.1.3 | DAST + Manual | 🔴 Critical |
| ST-02 | IDOR on Download | AC-02 | RS-01, RS-02 | V8.3.4, V4.2.1 | Manual + Auto | 🔴 Critical |
| ST-03 | Malicious File Upload | AC-03 | RS-03, RS-05 | V12.2.1, V5.1.3 | Manual | 🔴 Critical |
| ST-04 | Brute Force Login | AC-04 | RS-01, RS-06, RS-10 | V2.2.1, V2.2.4 | Automated | 🔴 Critical |
| ST-05 | JWT Token Replay | AC-05 | RS-01, RS-09 | V3.5.2, V3.2.1 | Manual | 🟡 Medium |
| ST-06 | Massive Upload DoS | AC-06 | RS-05, RS-10 | V12.2.3, V5.1.3 | Automated | 🔴 Critical |
| ST-07 | Unauthorised Delete | AC-07 | RS-02 | V4.2.2, V8.2.1 | Manual | 🟡 Medium |
| ST-08 | User Enumeration | AC-08 | RS-03, RS-09 | V2.2.5, V7.4.1 | Manual + Auto | 🔴 Critical |
| ST-09 | HTTPS + Security Headers | AC-05 | RS-09, RNF-01 | V9.1.1, V14.4.3 | Manual | 🟡 Medium |
| ST-10 | Password Hash Strength | AC-04 | RS-06 | V2.4.1, V2.4.2 | SAST + Review | 🔴 Critical |

### 3.1 Abuse Case Coverage

All 8 abuse cases from Element 3 are covered by at least one test case:

| Abuse Case | Description | Test(s) |
|------------|-------------|---------|
| AC-01 | Path Traversal | ST-01 |
| AC-02 | IDOR | ST-02 |
| AC-03 | Malicious Upload / RCE | ST-03 |
| AC-04 | Brute Force | ST-04, ST-10 |
| AC-05 | Stolen JWT | ST-05, ST-09 |
| AC-06 | Upload DoS | ST-06 |
| AC-07 | Unauthorised Delete | ST-07 |
| AC-08 | User Enumeration | ST-08 |

---

## 4. Summary

This document covers the following contributions for Phase 1:

- **10 test cases** defined at plan level (design-time), covering all 8 abuse cases from Element 3 with detailed steps, expected results and specific tools (OWASP ZAP, Burp Suite, Hydra, SonarQube, Snyk).
- **Complete bidirectional traceability matrix**: all abuse cases have test coverage, and all tests have risk justification through RS-XX requirements and ASVS 5.0 references.
- **Documented testing methodology**: risk-based testing with four complementary approaches (SAST, DAST, Manual Penetration Testing, Code Review), aligned with the course DevSecOps pipeline.
