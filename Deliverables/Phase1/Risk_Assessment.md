# Risk Assessment — Ender Chest

This document employs the **DREAD** risk assessment methodology to prioritise the threats identified in `Threat_modeling.md`. Each threat is scored across five dimensions and the average determines the overall risk level and mitigation priority.

---

## 1. Methodology

### 1.1 DREAD Model

**DREAD Score = (D + R + E + A + D) / 5**

Each dimension is scored on a scale of **1–10**:

| Dimension | Description | 1 (Low) | 5 (Medium) | 10 (High) |
|-----------|-------------|---------|-----------|----------|
| **D**amage Potential | How severe is the impact if successfully exploited? | Minimal, no data loss | Moderate — partial exposure or service degradation | Critical — full system compromise, all data exposed |
| **R**eproducibility | How reliably can the attack be reproduced? | Requires very specific conditions that rarely occur | Reproducible with some effort | Always reproducible; automated tools exist |
| **E**xploitability | How much skill/effort is required to exploit? | Requires advanced skills and significant effort | Requires intermediate knowledge | Trivial; script-kiddie level or fully automated |
| **A**ffected Users | How many users are impacted? | Single user, isolated | Multiple users | All users / entire system |
| **D**iscoverability | How easy is it to find the vulnerability? | Very difficult, requires deep source-code review | Discoverable with black-box testing | Publicly documented / automated scanners detect it |

**Risk Level Classification:**

| Score Range | Risk Level |
|-------------|------------|
| 7.5 – 10.0 | **CRITICAL** |
| 5.0 – 7.4 | **HIGH** |
| 2.5 – 4.9 | **MEDIUM** |
| 1.0 – 2.4 | **LOW** |

---

## 2. DREAD Scoring per Threat

### CRITICAL Risks (Score ≥ 7.5)

---

#### RISK-01 — Path Traversal (T-05)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 10 | Could write files anywhere on the server (overwrite config, deploy web shell → RCE). Complete system compromise. |
| **R**eproducibility | 9 | Adding `../../` to a filename is always reproducible; automated scanners do this automatically. |
| **E**xploitability | 7 | Requires basic HTTP knowledge; no special tooling needed — any HTTP client suffices. |
| **A**ffected Users | 9 | If OS files are overwritten or a web shell is deployed, all users (and the server) are affected. |
| **D**iscoverability | 9 | CWE-22; OWASP Top 10; well-documented and detected by all standard DAST tools. |
| **DREAD Score** | **8.8** | **CRITICAL** |

**Priority:** Highest.  
**Mitigations:** UUID physical filenames; `Path.normalize()` + base-directory validation; filename sanitisation (SDR-04).

---

#### RISK-02 — Malicious File Upload / Web Shell (T-06)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 10 | Remote Code Execution upon web shell access → full server compromise. |
| **R**eproducibility | 8 | Bypassing Content-Type checks is trivially reproducible with curl or Burp Suite. |
| **E**xploitability | 6 | Requires understanding of MIME types and HTTP multipart; readily available tutorials. |
| **A**ffected Users | 9 | Server compromise affects all users' data and system availability. |
| **D**iscoverability | 8 | OWASP Top 10 A04; well-known attack class; DAST scanners test for it. |
| **DREAD Score** | **8.2** | **CRITICAL** |

**Mitigations:** Magic-byte MIME validation (Apache Tika); files stored outside web root; no execute permissions; UUID filenames (SDR-03, SDR-05).

---

#### RISK-03 — IDOR — Object-level Authorisation Bypass (T-07)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 9 | Unauthorized read of any user's private files; potential data breach / privacy violation. |
| **R**eproducibility | 9 | Change UUID in URL → access foreign resource; completely reproducible. |
| **E**xploitability | 8 | Trivial with any HTTP client; no special skills needed once authenticated. |
| **A**ffected Users | 10 | Every user's files are potentially accessible — entire user base affected. |
| **D**iscoverability | 9 | OWASP API Security Top 10 #1 (BOLA); widely known and actively tested. |
| **DREAD Score** | **9.0** | **CRITICAL** |

**Mitigations:** Object-level AccessShare check per resourceId for every API operation (SDR-02).

---

#### RISK-04 — SQL Injection (T-11)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 10 | Full database exfiltration (all user credentials, files, access records); potential data deletion or DDL execution. |
| **R**eproducibility | 8 | SQL injection payloads are well-known and always reproducible if the vulnerability exists. |
| **E**xploitability | 7 | Automated tools (SQLMap) make exploitation trivial once the injection point is found. |
| **A**ffected Users | 10 | All user data in the database is exposed. |
| **D**iscoverability | 9 | OWASP Top 10 A03; automated DAST scanners and SQLMap detect it. |
| **DREAD Score** | **8.8** | **CRITICAL** |

**Mitigations:** JDBC prepared statements exclusively; JPA named queries; DML-only DB user (SDR-03, SDR-NEW-06).

---

### HIGH Risks (Score 5.0 – 7.4)

---

#### RISK-05 — Credential Brute Force / Stuffing (T-10)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 8 | Account takeover → access to all victim's files and shares. |
| **R**eproducibility | 9 | Fully automatable with tools like Hydra, Burp Intruder. |
| **E**xploitability | 8 | Script-kiddie level; credential lists are publicly available. |
| **A**ffected Users | 6 | One account per attack attempt, but scalable across all users. |
| **D**iscoverability | 7 | Any publicly exposed login endpoint is a known target. |
| **DREAD Score** | **7.6** | **HIGH** |

**Mitigations:** Rate limiting on `/auth/login`; account lockout (IsLocked); generic error messages (SDR-10, SDR-01).

---

#### RISK-06 — JWT Algorithm Confusion / Forgery (T-01)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 9 | Authentication bypass → impersonate any user including Admin. |
| **R**eproducibility | 7 | Reproducible if the library accepts `alg: none`; requires JWT knowledge. |
| **E**xploitability | 5 | Requires understanding of JWT internals; available PoC tools. |
| **A**ffected Users | 8 | Attacker can target any user or gain admin privileges. |
| **D**iscoverability | 7 | Well-documented CVE class; JWT toolkits like jwt_tool test for it. |
| **DREAD Score** | **7.2** | **HIGH** |

**Mitigations:** Server-side algorithm whitelist; reject `alg: none`; validate `iss`, `exp`, `sub` (SDR-01).

---

#### RISK-07 — Role Abuse — EDITOR Deletes Files (T-09)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 6 | Unauthorised deletion of files owned by others; data loss for owners. |
| **R**eproducibility | 8 | Simply send DELETE with EDITOR JWT; fully reproducible. |
| **E**xploitability | 8 | Any EDITOR role user can attempt this; no special skill needed. |
| **A**ffected Users | 5 | Affects owners of resources the attacker has EDITOR access to. |
| **D**iscoverability | 6 | Requires knowing the RBAC model; moderately discoverable. |
| **DREAD Score** | **6.6** | **HIGH** |

**Mitigations:** RBAC matrix: DELETE is OWNER-only; EDITOR returns HTTP 403; soft delete limits data loss (SDR-02).

---

#### RISK-08 — Weak Password Hashing (T-14)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 9 | All user passwords recoverable from DB dump → cascading account takeovers. |
| **R**eproducibility | 7 | Requires a DB breach first, then hash cracking. |
| **E**xploitability | 5 | Requires DB access + cracking tools (Hashcat); intermediate effort. |
| **A**ffected Users | 10 | Every registered user's credentials compromised. |
| **D**iscoverability | 4 | Requires DB access; not discoverable from the outside. |
| **DREAD Score** | **7.0** | **HIGH** |

**Mitigations:** BCrypt or Argon2 with appropriate cost factor; never store plaintext (SDR-06).

---

#### RISK-09 — Denial of Service via Large File Uploads (T-08 + T-18)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 7 | Disk exhaustion prevents all uploads; potential application crash (OOM). |
| **R**eproducibility | 9 | Trivially reproducible by any authenticated user with a large file. |
| **E**xploitability | 9 | curl with a large body is all that is needed. |
| **A**ffected Users | 8 | All users lose upload capability if disk fills. |
| **D**iscoverability | 6 | Requires testing upload limits; moderately discoverable. |
| **DREAD Score** | **7.8** | **CRITICAL** |

> **Note:** Despite being categorised as DoS, the high reproducibility and exploitability scores push this to CRITICAL.

**Mitigations:** Max file size before buffering; per-user StorageQuota; rate limiting on upload endpoint (SDR-05, SDR-NEW-07, SDR-10).

---

#### RISK-10 — Audit Log Tampering (T-13)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 8 | Erases evidence of malicious activity; incident response impossible. |
| **R**eproducibility | 5 | Requires OS-level server access; not easily reproducible from outside. |
| **E**xploitability | 4 | Requires OS access; insider or post-exploitation scenario. |
| **A**ffected Users | 7 | All users lose protection from undetected malicious activity. |
| **D**iscoverability | 3 | Only discoverable after server compromise; not externally visible. |
| **DREAD Score** | **5.4** | **HIGH** |

**Mitigations:** Real-time forwarding to external ELK/SIEM before response; logs not stored exclusively locally (FR-08, SDR-NEW-03).

---

### MEDIUM Risks (Score 2.5 – 4.9)

---

#### RISK-11 — File Integrity Tampering on Disk (T-17)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 8 | Delivery of malicious or corrupted content to users. |
| **R**eproducibility | 4 | Requires OS-level access; not externally reproducible. |
| **E**xploitability | 3 | Requires insider or post-exploitation OS access. |
| **A**ffected Users | 6 | Users who download the tampered file are affected. |
| **D**iscoverability | 2 | Not discoverable without source code review or OS access. |
| **DREAD Score** | **4.6** | **MEDIUM** |

**Mitigations:** SHA-256 FileHash stored in FileVersion; verified on every download; abort on mismatch (SDR-NEW-11).

---

#### RISK-12 — Internal Error Information Disclosure (T-04)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 4 | Exposes internal paths, stack traces, framework versions — useful for attackers. |
| **R**eproducibility | 8 | Easily triggered with malformed inputs; always reproducible. |
| **E**xploitability | 8 | No skill required — send invalid input, observe response. |
| **A**ffected Users | 3 | Primarily benefits the attacker; indirectly affects all users. |
| **D**iscoverability | 7 | Any automated scanner will trigger error conditions. |
| **DREAD Score** | **6.0** | **HIGH** |

> **Note:** Reclassified to HIGH due to high reproducibility and exploitability scores.

**Mitigations:** Global exception handler; generic error messages only; never expose stack traces (SDR-09).

---

#### RISK-13 — Sensitive Data in Audit Logs (T-19)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 7 | Passwords or tokens visible to log system operators → account takeover. |
| **R**eproducibility | 4 | Depends on accidental logging in code; not directly triggerable externally. |
| **E**xploitability | 3 | Requires access to the log system (insider). |
| **A**ffected Users | 8 | Any user whose credentials are logged is affected. |
| **D**iscoverability | 2 | Requires log system access; not externally discoverable. |
| **DREAD Score** | **4.8** | **MEDIUM** |

**Mitigations:** Audit event schema explicitly excludes passwords, tokens, file content (RNF-04).

---

#### RISK-14 — Admin Endpoint Exposure (T-20)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 9 | Unauthenticated admin access → manage any user account, system config. |
| **R**eproducibility | 5 | Depends on misconfiguration; reproducible if Actuator is exposed. |
| **E**xploitability | 5 | Requires discovering the endpoint; tools like Shodan/Gobuster find it. |
| **A**ffected Users | 10 | All users if admin access is obtained. |
| **D**iscoverability | 6 | Spring Boot Actuator default paths are well-known. |
| **DREAD Score** | **7.0** | **HIGH** |

**Mitigations:** Restrict admin and Actuator endpoints to internal network; JWT Admin role required (SDR-02, SDR-09).

---

### LOW Risks (Score 1.0 – 2.4)

---

#### RISK-15 — User Enumeration via Login Error (T-16)

| Dimension | Score | Justification |
|-----------|-------|---------------|
| **D**amage Potential | 2 | Reveals which usernames exist; aids targeted brute force but limited standalone harm. |
| **R**eproducibility | 9 | Trivially reproducible if different error messages are returned. |
| **E**xploitability | 9 | No skill required; compare error messages for existing vs non-existing users. |
| **A**ffected Users | 2 | Exposes account existence only. |
| **D**iscoverability | 8 | Standard check in any auth testing checklist. |
| **DREAD Score** | **6.0** | **HIGH** |

> **Note:** Reclassified to HIGH due to very high reproducibility, exploitability, and discoverability. Even though damage potential is low in isolation, it significantly facilitates brute force (T-10).

**Mitigations:** Return identical generic error message `"Invalid credentials"` for both cases.

---

## 3. Prioritised Risk Register

| Risk ID | Threat(s) | DREAD Score | Level | Priority | Status |
|---------|-----------|-------------|-------|----------|--------|
| RISK-03 | T-07 IDOR | **9.0** | CRITICAL | 1 | Mitigated — AccessShare per resourceId |
| RISK-01 | T-05 Path Traversal | **8.8** | CRITICAL | 2 | Mitigated — UUID naming + path normalisation |
| RISK-04 | T-11 SQL Injection | **8.8** | CRITICAL | 3 | Mitigated — prepared statements |
| RISK-02 | T-06 Web Shell Upload | **8.2** | CRITICAL | 4 | Mitigated — magic-byte MIME check |
| RISK-09 | T-08/T-18 DoS Upload | **7.8** | CRITICAL | 5 | Mitigated — size limit + StorageQuota |
| RISK-05 | T-10 Brute Force | **7.6** | HIGH | 6 | Mitigated — rate limit + lockout |
| RISK-06 | T-01 JWT Spoofing | **7.2** | HIGH | 7 | Mitigated — algorithm whitelist |
| RISK-08 | T-14 Weak Passwords | **7.0** | HIGH | 8 | Mitigated — BCrypt/Argon2 |
| RISK-14 | T-20 Admin Exposure | **7.0** | HIGH | 9 | Mitigated — network restriction + Admin role |
| RISK-15 | T-16 User Enumeration | **6.0** | HIGH | 10 | Mitigated — generic error message |
| RISK-12 | T-04 Error Disclosure | **6.0** | HIGH | 11 | Mitigated — global exception handler |
| RISK-07 | T-09 Role Abuse | **6.6** | HIGH | 12 | Mitigated — RBAC matrix OWNER-only DELETE |
| RISK-10 | T-13 Log Tampering | **5.4** | HIGH | 13 | Mitigated — external ELK/SIEM |
| RISK-11 | T-17 File Integrity | **4.6** | MEDIUM | 14 | Mitigated — SHA-256 FileHash verification |
| RISK-13 | T-19 Sensitive Logs | **4.8** | MEDIUM | 15 | Mitigated — audit event schema |

---

## 4. Residual Risk

After applying all proposed mitigations, residual risk for all CRITICAL and HIGH items is reduced to **LOW** or **MEDIUM**, contingent on:

1. Correct implementation of JDBC prepared statements with no fallback to string concatenation (RISK-04).
2. Correct Java NIO path normalisation and base-directory validation on every file operation (RISK-01).
3. Continuous dependency updates and SCA scanning (SDR-07) to address newly discovered CVEs in Spring, JDBC drivers, and Apache Tika.
4. Periodic DREAD re-evaluation when new features are added or the threat landscape changes.
5. Phase 2 DAST scanning and penetration testing to validate that mitigations are correctly implemented.
