# Threat Modeling — Ender Chest

**Course:** DESOFS 2026  
**Group:** WED\_NAP\_3  
**Project:** Ender Chest — Secure File Management System  
**Phase:** 1  
**Last updated:** 2026-04-20

---

## 1. Methodology

**STRIDE per DFD element** is applied to all processes, data stores, data flows, and external entities at Level 1 and Level 2. Each DFD element is evaluated against all six STRIDE threat categories.

| Letter | Threat Type | Security Property Violated |
|--------|------------|---------------------------|
| **S** | Spoofing | Authentication |
| **T** | Tampering | Integrity |
| **R** | Repudiation | Non-repudiation |
| **I** | Information Disclosure | Confidentiality |
| **D** | Denial of Service | Availability |
| **E** | Elevation of Privilege | Authorisation |

---

## 2. STRIDE Analysis per DFD Element

### 2.1 External Entity: User (Browser / App)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-10** | S | **Credential Brute Force / Stuffing** — Attacker exhausts username/password combinations to gain account access, abusing the login endpoint. | External attacker | Automated tool sends many POST /auth/login requests with different credentials (wordlists, breach dumps). |
| **T-16** | I | **User Enumeration via Login Error** — Distinct error messages reveal whether a username exists in the system, enabling targeted attacks. | External attacker | Compare responses for "user not found" vs "wrong password"; observe HTTP status codes or response timing differences. |

---

### 2.2 External Entity: Administrator

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-20** | E | **Admin Endpoint Exposure** — Spring Boot Actuator or admin endpoints exposed to the internet, allowing unauthenticated or low-privilege access to sensitive management functions. | External attacker | Access `/actuator/env`, `/actuator/heapdump`, or `/admin/users` without authentication; admin endpoints reachable from untrusted network. |

---

### 2.3 Process: Spring Boot Application

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-01** | S | **JWT Algorithm Confusion** — Attacker forges a JWT by setting `alg: none` or performing HS256/RS256 confusion (using the public key as the HMAC secret). | External attacker | Craft JWT with `alg: none` in header; or encode payload signed with the server's RS256 public key as an HS256 HMAC secret. |
| **T-02** | T | **TLS Downgrade / MITM** — Attacker performs a man-in-the-middle attack to intercept or modify traffic by downgrading from HTTPS to HTTP. | Network adversary | Strip HTTPS redirect; HSTS not set; intercept traffic and modify requests or responses in transit. |
| **T-03** | R | **Action Repudiation** — A user denies having uploaded, deleted, or shared a resource, and no reliable audit trail exists to refute the claim. | Malicious authenticated user | Perform a destructive action (delete, share leak); claim no knowledge; no audit trail to prove otherwise. |
| **T-04** | I | **Internal Error Information Disclosure** — Stack traces, exception messages, internal paths, or framework versions leaked in HTTP error responses. | External attacker | Trigger server error (malformed input, boundary conditions); inspect response body for stack traces or internal detail. |
| **T-08** | D | **DoS via Large File Uploads** — Attacker fills disk or exhausts memory/threads by uploading very large files or many concurrent requests without size enforcement. | External attacker / authenticated user | Send large multipart uploads repeatedly; open many concurrent upload connections. |
| **T-09** | E | **Role Abuse — EDITOR Performs DELETE** — An EDITOR attempts to delete a file they do not own, exploiting missing RBAC enforcement at the operation level. | Authenticated user with EDITOR role | Send `DELETE /files/{fileId}` with a valid EDITOR JWT. |

---

### 2.4 Data Flow: DF-01 — Authentication Request (User → App)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-10** | S | **Credential Brute Force / Stuffing** — Automated attacks against the login endpoint. | External attacker | Automated tool (Hydra, Burp Intruder) sends many POST /auth/login requests. |
| **T-16** | I | **User Enumeration via Login Error** — Distinct error messages or response timing differences reveal whether a username exists. | External attacker | Compare HTTP responses and timing for non-existent vs. existing usernames. |

---

### 2.5 Data Flow: DF-03 — File Upload (User → App)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-05** | T | **Path Traversal** — Attacker supplies a filename containing `../` sequences, null bytes, or URL-encoded traversal characters to escape the storage base directory and overwrite arbitrary server files. | External attacker | `filename = "../../../../etc/passwd"` or `"../webroot/shell.jsp"` in multipart upload field. |
| **T-06** | T | **Malicious File Upload / Web Shell** — Attacker uploads an executable file (JSP, PHP, shell script) by spoofing the Content-Type header, enabling Remote Code Execution if the file is later accessed. | External attacker | Upload file with `Content-Type: image/jpeg` but actual content is a JSP/PHP script; or send a polyglot file (valid JPEG header + executable payload). |
| **T-07** | E | **IDOR — Broken Object Level Authorisation** — Authenticated user uploads to a folder they are not authorised to write by guessing or enumerating folder UUIDs. | Authenticated malicious user | Supply a `folderId` UUID belonging to another user in the upload request. |
| **T-08** | D | **DoS via Large File Uploads** — No file size check allows disk exhaustion or memory exhaustion on the server. | External attacker | Multipart upload of very large file bodies without size enforcement. |

---

### 2.6 Data Flow: DF-04 — File Download (User → App)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-07** | E | **IDOR — Broken Object Level Authorisation** — Authenticated user accesses another user's file by manipulating the fileId UUID in the URL. | Authenticated malicious user | Change `fileId` UUID in `GET /files/{fileId}` to another user's UUID; authenticated but not authorised. |

---

### 2.7 Data Flow: DF-06 — File Delete (User → App)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-09** | E | **Role Abuse — EDITOR Performs DELETE** — EDITOR role should not be able to delete; absent RBAC enforcement allows it. | Authenticated EDITOR | Send DELETE /files/{fileId} with valid EDITOR JWT. |

---

### 2.8 Data Flow: DF-08 — Folder Operations (User → App)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-05b** | T | **Path Traversal in Folder Operations** — Attacker manipulates the folder name or path parameter to escape the storage directory during folder create, rename, or delete. | External attacker | `folderName = "../../etc"` or traversal sequences in PUT/DELETE path parameter for folder operations. |
| **T-07** | E | **IDOR on Folder Resources** — User accesses or modifies another user's folder by guessing or substituting the folderId UUID. | Authenticated malicious user | Substitute folderId in GET/PUT/DELETE /folders/{folderId} with another user's folderId. |

---

### 2.9 Data Flow: DF-09 — Admin User Management (Administrator → App)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-20** | E | **Admin Endpoint Access without Admin Role** — Regular user attempts to access admin-only endpoints. | Authenticated regular user | Send GET /admin/users with a non-Admin JWT. |

---

### 2.10 Data Flows: DF-10 / DF-11 — Application ↔ PostgreSQL

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-11** | T | **SQL Injection** — Attacker injects SQL through user-controlled input (filename, search queries, folderId) to exfiltrate or modify data. | External attacker | `filename = "' OR '1'='1"` in upload; SQL payload in any API parameter reaching the DB via string concatenation. |
| **T-12** | I | **Sensitive Data in Error Messages / Logs** — Internal DB errors, query details, or user data exposed through HTTP responses or log endpoints. | External attacker | Trigger DB error (malformed input, constraint violations); observe response body or leaked log endpoint. |
| **T-15** | E | **Excessive DB User Privileges** — The DB account used by the application has DDL permissions; SQL injection could DROP TABLE or CREATE a backdoor user, granting the attacker capabilities far beyond what the application should allow. | External attacker (via T-11) | Exploit SQL injection with `DROP TABLE` or `CREATE USER` statements if the DB user has DDL permissions. |

---

### 2.11 Data Flows: DF-12 / DF-13 — Application ↔ Physical File System

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-17** | T | **File Integrity Tampering on Disk** — Attacker with OS-level access modifies a binary file after it has been stored, making it appear legitimate when downloaded by a user. | Insider / OS-level attacker | Directly modify `/srv/files/{uuid}` on the server filesystem outside the application, bypassing the API. |
| **T-18** | D | **Disk Exhaustion** — Attacker fills the file storage partition, preventing new uploads and potentially crashing the application or OS. | External attacker / authenticated user | Upload many large files until disk space is exhausted. |

---

### 2.12 Data Store: PostgreSQL Database

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-11** | T | **SQL Injection** — User-supplied input interpolated into SQL queries allows manipulation of DB state. | External attacker | Craft SQL payloads in any input field that reaches a non-parameterised query. |
| **T-14** | I | **Plaintext / Weak Password Storage** — Password hashes stored in a reversible or weak format (MD5, SHA-1) are recoverable after a database breach. | Insider / DB breach | Direct read from the `users` table following a SQL injection or DB compromise. |
| **T-15** | E | **Excessive DB User Privileges** — DDL-enabled DB account allows destructive operations via SQL injection. | External attacker | Exploit SQL injection with DDL commands (DROP, CREATE, TRUNCATE). |

---

### 2.13 Data Store: Physical File System

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-17** | T | **File Integrity Tampering on Disk** — Stored binary files modified directly on disk outside the application. | Insider / OS-level attacker | Locate UUID-named file in /srv/files/ and modify its bytes directly. |
| **T-18** | D | **Disk Exhaustion** — Storage partition filled by excessive uploads without quota enforcement. | External attacker / authenticated user | Upload many files without per-user quota enforcement. |

---

### 2.14 Data Flow: DF-14 — Audit Logs (App → ELK/SIEM)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-13** | R | **Log Tampering / Absence of Audit Trail** — Attacker or insider deletes or modifies local log files to erase evidence of malicious activity. | Insider / attacker with server access | Delete or modify log files on the application server after performing malicious actions. |
| **T-19** | I | **Sensitive Data in Audit Logs** — Passwords, tokens, or file content accidentally included in audit events become visible to log system operators or via log exposure. | Insider (log system admin) | Read audit log entries containing sensitive fields (passwords, JWTs, file content). |

---

### 2.15 Sub-Process: P2.1 — File Request Handler (Level 2)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-05** | T | **Path Traversal via Filename** — Malicious filename escapes base storage directory. | External attacker | `filename = "../../../../etc/passwd"` in multipart upload. |
| **T-06** | T | **Web Shell Upload via MIME Bypass** — Executable uploaded with spoofed Content-Type header. | External attacker | Upload `shell.jsp` with `Content-Type: image/jpeg`. |
| **T-07** | E | **IDOR — Object-Level Authorisation Bypass** — Attacker accesses resources without an AccessShare record for the specific resourceId. | Authenticated user | Substitute another user's fileId or folderId in request URL. |
| **T-08** | D | **DoS via Upload** — Large file body exhausts disk/memory before size check fires. | External attacker | Multipart upload with very large body sent without size check. |
| **T-09** | E | **RBAC Role Abuse** — EDITOR or VIEWER performs OWNER-only operations. | Authenticated EDITOR/VIEWER | Send DELETE with EDITOR JWT. |

---

### 2.16 Sub-Process: P2.2 — File Store (Level 2)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-05** | T | **Path Traversal at I/O layer** — Defence-in-depth: even if P2.1 validated the input, a crafted PhysicalOsPath could resolve outside the base directory at actual I/O. | External attacker | Bypass P2.1 validation; supply path that resolves outside basedir. |
| **T-17** | T | **File Integrity Tampering** — File modified on disk after upload; served without integrity check. | Insider | Modify /srv/files/{uuid} directly; download returns tampered content without hash verification. |

---

### 2.17 Sub-Process: P2.3 — Metadata Store (Level 2)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-11** | T | **SQL Injection** — User-controlled values concatenated into SQL queries in P2.3. | External attacker | Inject SQL via filename, folderId, or search parameter reaching a non-parameterised query. |

---

### 2.18 Sub-Process: P2.4 — Audit Log Service (Level 2)

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-13** | R | **Repudiation / Log Tampering** — Audit events not forwarded before response, or stored only locally, allowing deletion to erase evidence. | Insider / attacker | Perform action; delete local logs before external forwarding completes. |
| **T-19** | I | **Sensitive Data Logged** — Passwords, JWTs, or file content accidentally included in audit event fields. | Insider | Read audit logs containing sensitive fields. |

---

## 3. Threat Summary Table

| ID | STRIDE | DFD Element | Description | Priority |
|----|--------|-------------|-------------|---------|
| **T-01** | S | Spring Boot App | JWT Algorithm Confusion | HIGH |
| **T-02** | T | Spring Boot App | TLS Downgrade / MITM | HIGH |
| **T-03** | R | Spring Boot App | Action Repudiation | MEDIUM |
| **T-04** | I | Spring Boot App | Internal Error Information Disclosure | HIGH |
| **T-05** | T | DF-03, P2.1, P2.2 | Path Traversal (upload + folder ops) | CRITICAL |
| **T-06** | T | DF-03, P2.1 | Malicious File Upload / Web Shell | CRITICAL |
| **T-07** | E | DF-03, DF-04, DF-08, P2.1 | IDOR — Object-Level Authorisation Bypass | CRITICAL |
| **T-08** | D | DF-03, P2.1, Spring Boot App | DoS via Large File Uploads | CRITICAL |
| **T-09** | E | DF-06, P2.1, Spring Boot App | Role Abuse (EDITOR performs DELETE) | HIGH |
| **T-10** | S | DF-01, User Entity | Credential Brute Force / Stuffing | HIGH |
| **T-11** | T | DF-10, PostgreSQL, P2.3 | SQL Injection | CRITICAL |
| **T-12** | I | DF-11, PostgreSQL | Sensitive Data in Error Messages | HIGH |
| **T-13** | R | DF-14, P2.4 | Log Tampering / No Audit Trail | HIGH |
| **T-14** | I | PostgreSQL | Weak Password Storage | HIGH |
| **T-15** | E | DF-10, PostgreSQL | Excessive DB User Privileges | HIGH |
| **T-16** | I | DF-01, User Entity | User Enumeration via Login Error | HIGH |
| **T-17** | T | DF-12, DF-13, Physical FS, P2.2 | File Integrity Tampering on Disk | MEDIUM |
| **T-18** | D | Physical FS, DF-03 | Disk Exhaustion (DoS) | CRITICAL |
| **T-19** | I | DF-14, P2.4 | Sensitive Data in Audit Logs | MEDIUM |
| **T-20** | E | Administrator Entity, DF-09 | Admin Endpoint Exposure | HIGH |

---

## 4. Mitigations

| Threat ID | Threat | Control | Requirements |
|-----------|--------|---------|--------------|
| **T-01** | JWT Algorithm Confusion | Server-side algorithm whitelist (RS256/HS256 only); explicit rejection of `alg: none`; validation of `iss`, `exp`, `sub`, `aud` claims | SDR-01, SDR-NEW-01 |
| **T-02** | TLS Downgrade / MITM | HTTPS/TLS 1.3 enforced; HSTS with long max-age; HTTP connections rejected | SDR-09, NFR-01 |
| **T-03** | Action Repudiation | Structured audit log with userId, action, resourceId, timestamp, sourceIP forwarded to ELK/SIEM before response | FR-08, SDR-NEW-03 |
| **T-04** | Error Information Disclosure | Global exception handler returns only generic messages; stack traces never exposed in production | SDR-09 |
| **T-05** | Path Traversal | UUID as physical filename (user-supplied filename never in path); `Path.normalize()` + base-directory validation before every file I/O; filename sanitisation (strip `../`, `/`, `\`, null bytes) | SDR-04 |
| **T-06** | Web Shell Upload | Magic-byte MIME validation via Apache Tika (ignores Content-Type header); MIME type whitelist; files stored outside web root; storage directory has no execute permissions; UUID filenames prevent URL prediction | SDR-03, SDR-05 |
| **T-07** | IDOR | Object-level AccessShare check for every API operation before any I/O — authentication alone is not sufficient; default deny if no AccessShare record exists | SDR-02 |
| **T-08** | DoS via Upload | Max file size enforced before buffering; per-user StorageQuota checked before write; rate limiting on upload endpoint (HTTP 429) | SDR-05, SDR-NEW-07, SDR-10 |
| **T-09** | Role Abuse | RBAC matrix enforced: DELETE is OWNER-only; EDITOR/VIEWER receive HTTP 403; soft delete limits damage even if bypass found | SDR-02 |
| **T-10** | Brute Force / Stuffing | Rate limiting on `/auth/login`; account lockout (`IsLocked=true`) after N failures; identical generic error message for all login failures | SDR-10, SDR-09 |
| **T-11** | SQL Injection | JDBC prepared statements and JPA named queries exclusively; no string concatenation in SQL; DML-only DB user | SDR-03, SDR-NEW-06 |
| **T-12** | Sensitive Data in Errors | Global exception handler; DB error messages never forwarded to HTTP response; sanitised logging fields | SDR-09 |
| **T-13** | Log Tampering | All audit events forwarded to external ELK/SIEM over HTTPS/TLS with API key **before** response is returned; logs not stored exclusively locally | FR-08, SDR-NEW-03 |
| **T-14** | Weak Password Storage | BCrypt or Argon2id with appropriate work factor; salt per password; never store plaintext or reversible hashes | SDR-06 |
| **T-15** | Excessive DB Privileges | Production DB user has DML-only permissions: SELECT, INSERT, UPDATE, DELETE — no DDL, no TRUNCATE | SDR-NEW-06 |
| **T-16** | User Enumeration | Identical error message `"Invalid credentials"` for both "user not found" and "wrong password"; no timing difference | SDR-09 |
| **T-17** | File Integrity Tampering | SHA-256 FileHash stored in FileVersion at upload; recomputed and verified on every download in P2.2; abort and log `DOWNLOAD_INTEGRITY_FAIL` on mismatch — tampered file never served | SDR-NEW-11 |
| **T-18** | Disk Exhaustion | Per-user StorageQuota checked before write; max file size enforced; rate limiting on upload | SDR-NEW-07, SDR-05, SDR-10 |
| **T-19** | Sensitive Data in Logs | Audit event schema: only timestamp, userId, action, resourceId, resourceType, sourceIP, outcome — no passwords, tokens, or file content | SDR-NEW-12 |
| **T-20** | Admin Endpoint Exposure | Spring Boot Actuator restricted to internal network via firewall; admin endpoints require JWT with explicit Admin role claim | SDR-02, SDR-09 |

---

## 5. STRIDE Coverage Matrix

| DFD Element | Type | S | T | R | I | D | E | Threats Found |
|-------------|------|---|---|---|---|---|---|---------------|
| User (Browser / App) | External Entity | T-10 | — | — | T-16 | — | — | T-10, T-16 |
| Administrator | External Entity | — | — | — | — | — | T-20 | T-20 |
| Spring Boot Application | Process | T-01 | T-02 | T-03 | T-04 | T-08 | T-09 | T-01–T-04, T-08, T-09 |
| DF-01 Authentication Request | Data Flow | T-10 | — | — | T-16 | — | — | T-10, T-16 |
| DF-03 File Upload | Data Flow | — | T-05, T-06 | — | — | T-08 | T-07 | T-05, T-06, T-07, T-08 |
| DF-04 File Download | Data Flow | — | — | — | — | — | T-07 | T-07 |
| DF-06 File Delete | Data Flow | — | — | — | — | — | T-09 | T-09 |
| DF-08 Folder Operations | Data Flow | — | T-05b | — | — | — | T-07 | T-05b, T-07 |
| DF-09 Admin Operations | Data Flow | — | — | — | — | — | T-20 | T-20 |
| DF-10/11 App ↔ PostgreSQL | Data Flow | — | T-11 | — | T-12 | — | T-15 | T-11, T-12, T-15 |
| DF-12/13 App ↔ File System | Data Flow | — | T-17 | — | — | T-18 | — | T-17, T-18 |
| DF-14 Audit Log Forward | Data Flow | — | — | T-13 | T-19 | — | — | T-13, T-19 |
| PostgreSQL Database | Data Store | — | T-11 | — | T-14 | — | T-15* | T-11, T-14, T-15 |
| Physical File System | Data Store | — | T-17 | — | — | T-18 | — | T-17, T-18 |
| P2.1 File Request Handler | Process (L2) | — | T-05, T-06 | — | — | T-08 | T-07, T-09 | T-05–T-09 |
| P2.2 File Store | Process (L2) | — | T-05, T-17 | — | — | — | — | T-05, T-17 |
| P2.3 Metadata Store | Process (L2) | — | T-11 | — | — | — | — | T-11 |
| P2.4 Audit Log Service | Process (L2) | — | — | T-13 | T-19 | — | — | T-13, T-19 |

---

## 6. References

| Document | Location |
|----------|----------|
| DFD Level 0 source (pytm) | [DFD/DFD lvl0.py](./DFD/DFD%20lvl0.py) |
| DFD Level 1 source (pytm) | [DFD/DFD lvl1.py](./DFD/DFD%20lvl1.py) |
| DFD Level 2 source (pytm) | [DFD/DFD lvl2.py](./DFD/DFD%20lvl2.py) |
| DFD documentation | [DFDs.md](./DFDs.md) |
| Risk Assessment (DREAD) | [Risk_Assessment.md](./Risk_Assessment.md) |
| Abuse Cases | [Abuses_Cases.md](./Abuses_Cases.md) |
| Security Requirements | [Requirements.md](./Requirements.md) |
| Security Testing Plan | [Security_Testing.md](./Security_Testing.md) |
| Main Document | [Main_Document.md](./Main_Document.md) |
