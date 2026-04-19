# Abuse Cases — Ender Chest

Abuse cases describe how a malicious or misusing actor can exploit the system's functionality. They complement the functional use cases defined in `Requirements.md` and are derived directly from the threats identified in `Threat_modeling.md`.

Each abuse case follows the format:
- **Actor** — who performs the abuse
- **Preconditions** — what the attacker needs
- **Steps** — what they do
- **Impact** — what happens if successful
- **Countermeasures** — implemented mitigations (linked to SDR/FR IDs)
- **Related Threats** — linked to threat IDs in `Threat_modeling.md`

---

## AC-01 — JWT Algorithm Confusion Attack

**Related Threats:** T-01  
**Actor:** External attacker (unauthenticated or authenticated)

**Preconditions:**
- The server exposes a public key (RS256) or accepts `alg: none`.

**Steps:**
1. Attacker intercepts or crafts a JWT.
2. Changes the `alg` header to `none` or to `HS256` using the server's public key as the HMAC secret.
3. Forges any claims (e.g., sets `role: ADMIN`, arbitrary `sub`).
4. Sends the crafted token to the API.

**Impact:**
- Attacker gains administrative or arbitrary user privileges without valid credentials.
- Full system compromise possible (file access, account manipulation).

**Countermeasures:**
- Server enforces a strict algorithm whitelist (HS256 or RS256 only); explicitly rejects `alg: none`. (SDR-01)
- JWT library configured to ignore client-supplied algorithm headers.

---

## AC-02 — Path Traversal via File Upload

**Related Threats:** T-05  
**Actor:** Authenticated user (any role)

**Preconditions:**
- User is registered and authenticated (valid JWT).
- User has at least EDITOR or OWNER role on a folder.

**Steps:**
1. Attacker sends `POST /files/upload` with a crafted filename such as `../../../../etc/passwd` or `../webroot/shell.jsp`.
2. If the server uses the supplied filename as the physical storage path, the file is written outside the intended directory.

**Impact:**
- Overwrite of critical OS files.
- Deployment of a web shell enabling Remote Code Execution (RCE).
- Exfiltration of sensitive server-side files.

**Countermeasures:**
- Original filename is **never** used as the physical file path on disk; only a system-generated UUID is used (PhysicalOsPath). (SDR-04)
- Path normalised with `java.nio.file.Path.normalize()` and verified to start with the configured base directory before write.
- Filename sanitised in metadata (strip `../`, `/`, `\`, null bytes) before storing display name.

---

## AC-03 — Web Shell Upload via MIME Type Bypass

**Related Threats:** T-06  
**Actor:** Authenticated user (EDITOR or OWNER role)

**Preconditions:**
- User has EDITOR or OWNER role on a folder.
- Server accepts file uploads.

**Steps:**
1. Attacker uploads a file with a legitimate-looking Content-Type header (`image/jpeg`) but with file content that is actually a JSP/PHP script.
2. If the server trusts Content-Type without inspecting the actual bytes, the executable script is stored.
3. Attacker navigates to the stored file URL to trigger execution.

**Impact:**
- Execution of arbitrary server-side code (Remote Code Execution).
- Full server compromise.

**Countermeasures:**
- File type validated using magic bytes via Apache Tika, ignoring the client-supplied Content-Type header. (SDR-03)
- Files stored outside the web root — not directly accessible via static URL.
- Storage directory has no execute permissions.
- UUID filename prevents attacker from knowing the URL to trigger execution.

---

## AC-04 — IDOR — Access Another User's Files

**Related Threats:** T-07  
**Actor:** Authenticated user (any role on their own resources)

**Preconditions:**
- Attacker is authenticated with a valid JWT.
- Attacker knows (or guesses) the UUID of another user's file.

**Steps:**
1. Attacker observes a `fileId` UUID (e.g., from a shared link or by incremental enumeration attempt).
2. Sends `GET /files/{targetFileId}` with their own valid JWT.
3. If access control only checks "is the user authenticated?" rather than "does this user have an AccessShare record for this specific fileId?", the file is served.

**Impact:**
- Unauthorised access to other users' private files.
- Data breach, privacy violation.

**Countermeasures:**
- Every file/folder operation performs an object-level authorisation check: verifies that the calling user has an AccessShare record with a valid RoleType for the specific resourceId. (SDR-02)
- Being authenticated alone is not sufficient — the AccessShare aggregate must explicitly grant access.

---

## AC-05 — Credential Brute Force / Stuffing

**Related Threats:** T-10  
**Actor:** External attacker (unauthenticated)

**Preconditions:**
- The login endpoint is publicly accessible.
- Attacker has a list of common passwords or credentials from a previous breach.

**Steps:**
1. Attacker sends automated requests to `POST /auth/login` with many username/password combinations.
2. Attempts to find valid credentials.

**Impact:**
- Account takeover of legitimate users.
- If an OWNER account is compromised, all shared files and user data are exposed.

**Countermeasures:**
- Rate limiting on `POST /auth/login` returns HTTP 429 after threshold exceeded. (SDR-10)
- Account locked (`IsLocked=true`) after N consecutive failed login attempts for the same username.
- Identical error message for "user not found" and "wrong password" (prevents user enumeration).
- Attacker cannot determine which accounts exist.

---

## AC-06 — Role Escalation — EDITOR Deletes Files

**Related Threats:** T-09  
**Actor:** Authenticated user with EDITOR role

**Preconditions:**
- User has been granted EDITOR role on a file or folder via AccessShare.

**Steps:**
1. EDITOR sends `DELETE /files/{fileId}` with a valid JWT.
2. If the server only checks "is the user authenticated and has some access?", the delete proceeds.

**Impact:**
- Unauthorised deletion of files the attacker does not own.
- Data loss for the owner.

**Countermeasures:**
- RBAC matrix enforced: DELETE is **OWNER-only**. EDITOR and VIEWER requests return HTTP 403. (SDR-02)
- Soft delete (IsDeleted=true) prevents immediate permanent loss even if a bypass were found.

---

## AC-07 — SQL Injection via File Metadata

**Related Threats:** T-11  
**Actor:** Authenticated attacker

**Preconditions:**
- User is authenticated with any role.
- Any input reaching a database query is not parameterised.

**Steps:**
1. Attacker uploads a file with the filename `' OR '1'='1`.
2. If the filename is interpolated into a SQL query string, the injected SQL is executed.
3. Alternatively, crafts a search query parameter with SQL payload.

**Impact:**
- Data exfiltration (all user records, file metadata, AccessShare entries).
- Data manipulation (change roles, delete records).
- In worst case, OS command execution via DB stored procedures.

**Countermeasures:**
- All database queries use JDBC prepared statements or JPA named queries exclusively. String concatenation into SQL is prohibited. (SDR-03)
- DB user has DML-only permissions — no DDL, no stored procedure execution. (SDR-NEW-06)

---

## AC-08 — Denial of Service via Large File Uploads

**Related Threats:** T-08, T-18  
**Actor:** External attacker or authenticated user

**Preconditions:**
- User is authenticated (or, if rate limiting is absent on upload, even unauthenticated).

**Steps:**
1. Attacker sends many multipart upload requests with very large file bodies (e.g., hundreds of GBs).
2. Without size checks, the server buffers the entire file, exhausting memory or disk space.

**Impact:**
- Server memory exhaustion causing crash.
- Disk full, blocking all uploads from legitimate users.
- Application unavailability (DoS).

**Countermeasures:**
- Maximum file size enforced in Spring Boot (`max-file-size` property) — request rejected before buffering. (SDR-05)
- Per-user StorageQuota checked before writing to disk. (SDR-NEW-07)
- Rate limiting on the upload endpoint. (SDR-10)

---

## AC-09 — Log Tampering to Erase Evidence

**Related Threats:** T-13  
**Actor:** Insider or attacker with server OS access

**Preconditions:**
- Attacker has gained OS-level access to the application server.

**Steps:**
1. Attacker performs malicious actions (exfiltrates files, deletes accounts).
2. Deletes or modifies local log files to erase evidence.

**Impact:**
- Incident response is impossible — no evidence of malicious activity.
- Breach goes undetected.

**Countermeasures:**
- All audit events forwarded in real time to an external ELK/SIEM over HTTPS/TLS with API key before the response is returned. (FR-08, SDR-NEW-03)
- Logs are **not** stored exclusively on the local server.
- The external ELK system is the immutable audit trail — local log deletion does not erase the forwarded events.

---

## AC-10 — File Integrity Tampering on Disk

**Related Threats:** T-17  
**Actor:** Insider with OS-level access to the file storage directory

**Preconditions:**
- Attacker has OS-level access to `/srv/files/` (or equivalent storage directory).

**Steps:**
1. Attacker locates a stored binary file by UUID name.
2. Modifies or replaces its content directly on disk (without going through the API).
3. When a legitimate user downloads the file, they receive the tampered content.

**Impact:**
- Delivery of malicious or modified content to users (supply chain attack, data manipulation).
- Breach of data integrity guarantees.

**Countermeasures:**
- On every download, `P2.2 File Store` recomputes SHA-256 of the read bytes and compares to the stored `FileVersion.FileHash`. (SDR-NEW-11)
- If hashes differ, the download is aborted (HTTP 500), an integrity alert is logged (`DOWNLOAD_INTEGRITY_FAIL`), and the file is NOT served.
- File directory restricted to the application OS user only (no public access).

---

## Summary Table

| ID | Actor | Abuse | Threats | Impact | Key Countermeasure |
|----|-------|-------|---------|--------|-------------------|
| AC-01 | External | JWT Algorithm Confusion | T-01 | Privilege escalation | Algorithm whitelist; reject `alg: none` |
| AC-02 | Authenticated user | Path Traversal via Upload | T-05 | RCE, file overwrite | UUID physical name; path normalisation |
| AC-03 | Authenticated user | Web Shell Upload | T-06 | RCE | Magic-byte MIME validation; out-of-webroot storage |
| AC-04 | Authenticated user | IDOR — Access foreign files | T-07 | Data breach | Object-level AccessShare check per resourceId |
| AC-05 | External | Credential Brute Force | T-10 | Account takeover | Rate limiting; account lockout |
| AC-06 | EDITOR role user | Delete files without ownership | T-09 | Data loss | RBAC matrix: OWNER-only DELETE |
| AC-07 | Authenticated user | SQL Injection | T-11 | Data exfiltration/modification | Prepared statements; DML-only DB user |
| AC-08 | Any user | DoS via large uploads | T-08, T-18 | Availability loss | File size limit; StorageQuota; rate limit |
| AC-09 | Insider | Log tampering | T-13 | Cover tracks, no audit | External ELK/SIEM; real-time forwarding |
| AC-10 | Insider | File integrity tampering | T-17 | Malicious content delivery | SHA-256 FileHash verification on download |
