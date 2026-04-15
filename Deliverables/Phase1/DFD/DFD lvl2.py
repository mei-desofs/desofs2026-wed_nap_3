#!/usr/bin/env python3
"""
DESOFS 2025/2026 — Secure File Management System
Phase 1 — Threat Modeling: Data Flow Diagram — Level 2 (File Service Detail)

Elemento 2

Level 2 — File Service Decomposition:
  At Level 1 the entire Spring Boot application appears as a single process.
  At Level 2 we decompose the File Service sub-system (which handles upload,
  download and delete — the highest threat-density area of the system) into
  its four internal sub-processes:

    P2.1  Input Validation
          Normalises filename/path, validates MIME type via magic bytes,
          checks file size against the configured limit, and applies
          rate limiting. This is the first defence line before any
          authentication or I/O is attempted.

    P2.2  Authorisation Check (RBAC via AccessShare)
          Validates the JWT (algorithm, signature, expiry), then resolves
          the caller's RoleType (OWNER | EDITOR | VIEWER) from the
          AccessShare aggregate for the requested resource. Object-level
          authorisation is enforced here — not just endpoint-level.

    P2.3  File Store (Binary I/O — Java NIO)
          Writes (upload) or reads (download) the binary file on the
          Physical File System. The filename stored on disk is always a
          system-generated UUID (FileVersion.PhysicalOsPath) — the
          user-supplied original filename is NEVER used as a path
          component. Path is normalised and validated against the base
          directory before any I/O.

    P2.4  Metadata Store (PostgreSQL via JDBC)
          Persists or queries the File and FileVersion aggregates in
          PostgreSQL using prepared statements only. On upload, a
          FileHash (SHA-256) is computed and stored alongside the
          PhysicalOsPath and MimeType. On download, the FileHash is
          retrieved and used to verify file integrity after the read.

  The Audit Log Service (P2.5) is also shown here because every File
  Service operation — upload, download, delete — must emit a structured
  audit event BEFORE returning a response to the caller. This makes the
  audit trail tamper-evident: a missing log entry after a network failure
  is detectable.

Threat mapping (from threat model Section 8):
  P2.1 Input Validation  ← T-05 Path Traversal
                           T-06 Malicious File Upload (Web Shell / RCE)
                           T-08 DoS by Upload (file size / rate limit)
  P2.2 Authorisation     ← T-07 IDOR (missing object-level auth check)
                           T-09 Role Abuse (Editor performs delete)
  P2.3 File Store        ← T-05 Path Traversal (base-dir escape on I/O)
                           T-17 File Integrity Tampering on Disk
  P2.4 Metadata Store    ← T-11 SQL Injection (unparameterised queries)
                           T-12 Sensitive Data in Logs / Errors
  P2.5 Audit Log Service ← T-13 Repudiation (absence of audit trail)

Trust Boundaries at Level 2:
  boundary_a   — Internet / Application:
                 The calling User (browser/app) lives here.  All data
                 crossing this boundary is untrusted and must pass P2.1
                 and P2.2 before touching any data store.
  boundary_b   — Application / Infrastructure:
                 PostgreSQL and the Physical File System live here.
                 Only the sub-processes P2.3 and P2.4 (running inside
                 the Spring Boot JVM) may cross this boundary.
  boundary_c   — Application / External Log System:
                 The ELK/SIEM lives here. P2.5 crosses this boundary
                 outbound with structured JSON audit events over
                 HTTPS/TLS authenticated via API key.

DFD Notation (T3 slides):
  Actor      → External Entity  (rectangle)
  Server     → Process          (circle / ellipse)
  Datastore  → Data Store       (two parallel lines)
  Boundary   → Trust Boundary   (dashed line)
  Dataflow   → Data Flow        (arrow)

Data flow numbering:
  Flows DF-L2-01 … DF-L2-16 are internal to the File Service.
  They correspond to the single DF-03 (upload), DF-04/DF-05 (download)
  and DF-06 (delete) flows visible at Level 1, and are numbered with
  the "L2" prefix to distinguish them from the Level 1 DF-XX identifiers.

Run:
  python3 DFD_lvl2.py --dfd | dot -Tpng -o dfd_level2.png
  python3 DFD_lvl2.py --dfd | dot -Tsvg -o dfd_level2.svg
"""

from pytm import (
    TM,
    Actor,
    Server,
    Datastore,
    Dataflow,
    Boundary,
    TLSVersion,
)

# ─────────────────────────────────────────────────────────────────────────────
# THREAT MODEL
# ─────────────────────────────────────────────────────────────────────────────
tm = TM("Secure File Management System — Level 2 File Service")
tm.description = (
    "Level 2 DFD decomposing the File Service sub-system of the Spring Boot "
    "monolith. Shows the four internal sub-processes (Input Validation, "
    "Authorisation Check, File Store, Metadata Store) plus the Audit Log "
    "Service, with trust boundaries separating the untrusted caller from the "
    "application logic and the infrastructure data stores."
)
tm.isOrdered = True
tm.mergeResponses = True

# ─────────────────────────────────────────────────────────────────────────────
# TRUST BOUNDARIES
# ─────────────────────────────────────────────────────────────────────────────

# Boundary A — Internet / Application
# The calling User originates from the untrusted internet. All request data
# (file content, filename, JWT, headers) crosses this boundary and must be
# treated as untrusted until validated by P2.1 and authorised by P2.2.
boundary_a = Boundary("Trust Boundary A — Internet / Application")

# Boundary B — Application / Infrastructure
# Separates the Spring Boot JVM (where P2.1–P2.5 execute) from the
# infrastructure data stores: PostgreSQL and the Physical File System.
# Only the application process account may access these stores.
# PostgreSQL is accessed via JDBC with a DML-only DB user.
# The filesystem directory is outside the web root with no execute permissions.
boundary_b = Boundary("Trust Boundary B — Application / Infrastructure")

# Boundary C — Application / External Log System
# The ELK/SIEM log aggregation system lives here. Structured JSON audit events
# cross this boundary outbound from P2.5 over HTTPS/TLS with API-key auth.
# This boundary exists to make the log forwarding crossing explicit in the DFD.
boundary_c = Boundary("Trust Boundary C — Application / External Log System")

# ─────────────────────────────────────────────────────────────────────────────
# EXTERNAL ENTITIES  —  Actor (rectangle in DFD)
# ─────────────────────────────────────────────────────────────────────────────

user = Actor("User (Browser / App)")
user.description = (
    "An authenticated end user interacting with the File Service via a "
    "browser or REST client. Carries a JWT access token in the Authorization "
    "header. May hold the role OWNER, EDITOR or VIEWER on a given resource "
    "as determined by the AccessShare aggregate. "
    "Untrusted — all input must be validated by P2.1 before processing."
)
user.inBoundary = boundary_a

ext_log = Actor("External Log System (ELK / SIEM)")
ext_log.description = (
    "External log aggregation system that receives structured JSON audit "
    "events from the Audit Log Service (P2.5) in real time. "
    "Write-only, authenticated via API key over HTTPS/TLS. "
    "Provides the immutable audit trail required for non-repudiation (T-13)."
)
ext_log.inBoundary = boundary_c

# ─────────────────────────────────────────────────────────────────────────────
# PROCESSES  —  Server (circle / ellipse in DFD)
# These are the internal sub-processes of the File Service, decomposed from
# the single "Spring Boot Application" process visible at Level 1.
# All run inside the same Spring Boot JVM — they are logical sub-processes,
# not separate services.
# ─────────────────────────────────────────────────────────────────────────────

p21 = Server("P2.1 Input Validation")
p21.description = (
    "First line of defence — executed before any authentication or I/O. "
    "Responsibilities: "
    "(1) Filename sanitisation: strip directory separators, null bytes and "
    "    control characters from the user-supplied filename. "
    "(2) Path normalisation: resolve the candidate storage path with "
    "    java.nio.file.Path.normalize() and verify it starts with the "
    "    configured base directory — reject any path that escapes it "
    "    (prevents T-05 Path Traversal). "
    "(3) MIME-type validation: read the first N bytes of the file content "
    "    (magic bytes) using Apache Tika — never trust the Content-Type "
    "    header sent by the client (prevents T-06 Web Shell upload). "
    "(4) File size check: reject uploads exceeding the configured maximum "
    "    (application.properties: file.max-size) before writing anything to "
    "    disk (mitigates T-08 DoS by upload). "
    "(5) Rate limiting: enforce per-user upload rate limit via token-bucket "
    "    filter; return HTTP 429 if exceeded (RS-10). "
    "If any check fails the request is rejected immediately with a generic "
    "error message — no partial write occurs."
)
p21.protocol = "Internal (Spring Boot JVM)"
p21.inBoundary = boundary_a

p22 = Server("P2.2 Authorisation Check (RBAC)")
p22.description = (
    "Enforces authentication and object-level authorisation before any "
    "data store is accessed. "
    "Responsibilities: "
    "(1) JWT validation: verify signature, algorithm (HS256/RS256 only — "
    "    reject 'none'), expiry and issuer claims (RS-01, RS-NEW-01). "
    "(2) AccessShare resolution: query the AccessShare aggregate for the "
    "    (resourceId, callerUserId) pair to determine the caller's RoleType "
    "    (OWNER | EDITOR | VIEWER). "
    "(3) Operation authorisation: apply the RBAC matrix — "
    "    OWNER: all operations; "
    "    EDITOR: upload, download; "
    "    VIEWER: download only. "
    "    DELETE is OWNER-only — an EDITOR sending DELETE is rejected here "
    "    (prevents T-09 role abuse). "
    "(4) Object-level check: confirm the requested resourceId belongs to a "
    "    resource the caller has access to — not just that they are "
    "    authenticated (prevents T-07 IDOR). "
    "If authorisation fails, return HTTP 403 with a generic error — never "
    "reveal whether the resource exists (prevents information disclosure)."
)
p22.protocol = "Internal (Spring Boot JVM)"
p22.usesSessionTokens = True
p22.inBoundary = boundary_a

p23 = Server("P2.3 File Store (Java NIO / OS I/O)")
p23.description = (
    "Handles binary file I/O on the Physical File System via Java NIO. "
    "Upload path: "
    "(1) Generate a new UUID for this FileVersion (PhysicalOsPath). "
    "    The user-supplied original filename is NEVER used as a path "
    "    component — it is stored only as metadata in PostgreSQL. "
    "(2) Resolve full path: basedir + '/' + UUID. Normalise and verify "
    "    the resolved path is still inside basedir (defence-in-depth "
    "    against T-05, even though P2.1 already validated the input). "
    "(3) Write file bytes via Files.write() or a streaming channel. "
    "(4) Compute SHA-256 hash of the written bytes — passed to P2.4 for "
    "    storage as FileVersion.FileHash (supports T-17 integrity check). "
    "Download path: "
    "(1) Retrieve PhysicalOsPath from FileVersion record (supplied by P2.4). "
    "(2) Normalise and validate path against basedir. "
    "(3) Read file bytes via Files.readAllBytes() or a streaming channel. "
    "(4) Verify SHA-256 hash against stored FileVersion.FileHash — raise "
    "    integrity alert and abort if mismatch (RS-NEW-11). "
    "Delete path: "
    "    File is NOT removed from disk here. The File aggregate's IsDeleted "
    "    flag is set to true by P2.4 (soft delete). Physical removal is a "
    "    separate scheduled cleanup process — preventing accidental data loss."
)
p23.protocol = "Java NIO (OS I/O)"
p23.inBoundary = boundary_b

p24 = Server("P2.4 Metadata Store (JDBC / PostgreSQL)")
p24.description = (
    "Persists and queries the File and FileVersion domain aggregates in "
    "PostgreSQL using prepared statements / JPA named queries only. "
    "String concatenation in SQL is prohibited (prevents T-11 SQL injection). "
    "Upload: INSERT into files and file_versions tables. "
    "    Stored fields include: FileId (UUID), FileName (sanitised original "
    "    name for display), OwnerId, FolderId, MimeType, Size, "
    "    PhysicalOsPath (UUID filename), FileHash (SHA-256 from P2.3), "
    "    UploadedAt, IsDeleted=false. "
    "Download: SELECT FileVersion record to retrieve PhysicalOsPath and "
    "    FileHash — supplied to P2.3 for the actual file read and integrity "
    "    verification. "
    "Delete: UPDATE files SET IsDeleted=true WHERE FileId=? — soft delete "
    "    only; physical file remains on disk until cleanup. "
    "StorageQuota check (upload): SELECT SUM(size) from file_versions WHERE "
    "    OwnerId=? to verify the upload will not exceed the user's quota "
    "    (RS-NEW-07). Reject with HTTP 429 if quota would be exceeded. "
    "DB user has DML-only permissions: SELECT, INSERT, UPDATE, DELETE. "
    "No DDL or administrative privileges (RS-NEW-06)."
)
p24.protocol = "JDBC / TLS"
p24.tlsVersion = TLSVersion.TLSv12
p24.inBoundary = boundary_b

p25 = Server("P2.5 Audit Log Service")
p25.description = (
    "Emits a structured JSON audit event for every File Service operation "
    "BEFORE the response is returned to the caller. "
    "This ordering ensures that a missing log entry after a failure is "
    "detectable — supporting non-repudiation (mitigates T-13). "
    "Event fields: timestamp (ISO-8601 UTC), userId, action "
    "(UPLOAD | DOWNLOAD | DELETE | DOWNLOAD_INTEGRITY_FAIL), "
    "resourceId (FileId), resourceType (FILE), sourceIP, "
    "outcome (SUCCESS | FAILURE), failureReason (generic, no stack trace). "
    "Logs are forwarded in real time to the External Log System (ELK/SIEM) "
    "over HTTPS/TLS authenticated via API key (RS-NEW-03). "
    "Logs are NOT stored exclusively on the local server — the external "
    "system provides the immutable audit trail. "
    "Sensitive data (passwords, tokens, file content) is NEVER logged "
    "(RNF-04). Generic error messages are used for failureReason to avoid "
    "disclosing internal system details (RS-09)."
)
p25.protocol = "HTTPS/TLS"
p25.tlsVersion = TLSVersion.TLSv13
p25.inBoundary = boundary_a

# ─────────────────────────────────────────────────────────────────────────────
# DATA STORES  —  Datastore (two parallel lines in DFD)
# ─────────────────────────────────────────────────────────────────────────────

db = Datastore("PostgreSQL Database")
db.description = (
    "Stores the File and FileVersion domain aggregates (and the AccessShare "
    "records queried by P2.2). "
    "Relevant fields for the File Service: "
    "  File        — FileId (UUID), FileName, FolderId, OwnerId, IsDeleted. "
    "  FileVersion — VersionId, FileId, PhysicalOsPath (UUID), Size, "
    "                MimeType, FileHash (SHA-256), UploadedAt. "
    "  AccessShare — ShareId, ResourceId, ResourceType, GrantedToUserId, "
    "                RoleType (OWNER | EDITOR | VIEWER). "
    "Accessed exclusively via JDBC with prepared statements / JPA named "
    "queries. DB user has DML-only permissions (no DDL, no TRUNCATE)."
)
db.isEncrypted = True
db.isSQL = True
db.inBoundary = boundary_b

filesystem = Datastore("Physical File System (/srv/files/)")
filesystem.description = (
    "Server filesystem directory outside the web root. "
    "Stores binary file content. Files are named using system-generated UUIDs "
    "(FileVersion.PhysicalOsPath) — the user-supplied original filename is "
    "never present on disk. "
    "Directory permissions: readable and writable by the Spring Boot process "
    "OS user only. No execute permissions on the directory or its contents. "
    "Path: /srv/files/{uuid} (configurable via application.properties). "
    "Accessed by P2.3 via Java NIO (Files.write / Files.readAllBytes). "
    "Physical file removal happens only via a scheduled cleanup process "
    "(after IsDeleted=true has been confirmed in PostgreSQL)."
)
filesystem.isEncrypted = False
filesystem.inBoundary = boundary_b

# ─────────────────────────────────────────────────────────────────────────────
# DATA FLOWS  —  Dataflow (arrow in DFD)
# Prefixed DF-L2-XX to distinguish from the Level 1 DF-XX identifiers.
# These flows detail the internal steps that at Level 1 are represented by
# the single DF-03 (upload), DF-04/DF-05 (download) and DF-06 (delete) flows.
# ─────────────────────────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════════════════════
# UPLOAD FLOW  (corresponds to Level 1: DF-03)
# ══════════════════════════════════════════════════════════════════════════════

# ── DF-L2-01  User → P2.1 : Raw upload request ───────────────────────────────
dfl201 = Dataflow(user, p21, "DF-L2-01: Raw Upload Request (multipart/form-data)")
dfl201.description = (
    "Authenticated user sends POST /files/upload with a multipart/form-data "
    "body containing: file binary content, original filename, target folderId. "
    "JWT access token in Authorization: Bearer header. "
    "This data is completely untrusted at this point — P2.1 will validate "
    "it before anything else happens."
)
dfl201.protocol = "HTTPS/TLS"
dfl201.tlsVersion = TLSVersion.TLSv13
dfl201.usesSessionTokens = True
dfl201.order = 1

# ── DF-L2-02  P2.1 → P2.2 : Validated upload request ────────────────────────
dfl202 = Dataflow(p21, p22, "DF-L2-02: Validated Upload Request")
dfl202.description = (
    "After P2.1 passes all checks (filename sanitised, path normalised and "
    "inside base dir, MIME validated via magic bytes, size within limit, "
    "rate limit not exceeded), the validated request is forwarded to P2.2 "
    "for authorisation. "
    "Data: sanitised filename, validated file bytes, folderId, JWT claims."
)
dfl202.protocol = "Internal (Spring Boot JVM)"
dfl202.order = 2

# ── DF-L2-03  P2.2 → PostgreSQL : AccessShare lookup ────────────────────────
dfl203 = Dataflow(p22, db, "DF-L2-03: AccessShare Lookup (JDBC)")
dfl203.description = (
    "P2.2 queries the AccessShare aggregate to resolve the caller's RoleType "
    "for the target folderId. "
    "Query (prepared statement): "
    "  SELECT role_type FROM access_share "
    "  WHERE resource_id = ? AND granted_to_user_id = ? "
    "  AND resource_type = 'FOLDER'. "
    "Also queries StorageQuota to check whether the upload would exceed the "
    "user's limit: "
    "  SELECT SUM(fv.size) FROM file_versions fv "
    "  JOIN files f ON fv.file_id = f.file_id "
    "  WHERE f.owner_id = ?."
)
dfl203.protocol = "JDBC / TLS"
dfl203.tlsVersion = TLSVersion.TLSv12
dfl203.order = 3

# ── DF-L2-04  PostgreSQL → P2.2 : AccessShare result ────────────────────────
dfl204 = Dataflow(db, p22, "DF-L2-04: AccessShare Result (JDBC)")
dfl204.description = (
    "PostgreSQL returns the caller's RoleType (OWNER or EDITOR — required for "
    "upload) and the current total storage used. "
    "If the role is VIEWER or the record does not exist, P2.2 returns HTTP 403. "
    "If the quota would be exceeded, P2.2 returns HTTP 429."
)
dfl204.protocol = "JDBC / TLS"
dfl204.tlsVersion = TLSVersion.TLSv12
dfl204.isResponse = True
dfl204.responseTo = dfl203
dfl204.order = 4

# ── DF-L2-05  P2.2 → P2.3 : Authorised upload ───────────────────────────────
dfl205 = Dataflow(p22, p23, "DF-L2-05: Authorised Upload — File Bytes")
dfl205.description = (
    "P2.2 has confirmed the caller holds OWNER or EDITOR role and the quota "
    "is not exceeded. File bytes and validated metadata are forwarded to P2.3 "
    "for physical storage. "
    "A new UUID is generated here for PhysicalOsPath."
)
dfl205.protocol = "Internal (Spring Boot JVM)"
dfl205.order = 5

# ── DF-L2-06  P2.3 → File System : Write binary file ────────────────────────
dfl206 = Dataflow(p23, filesystem, "DF-L2-06: Write Binary File (Java NIO)")
dfl206.description = (
    "P2.3 writes the file bytes to /srv/files/{uuid} via Java NIO. "
    "The UUID filename (PhysicalOsPath) is generated by the application — "
    "the user-supplied original filename is never part of the path. "
    "Path is normalised and verified to be inside the base directory. "
    "After writing, P2.3 computes SHA-256(file bytes) → FileHash."
)
dfl206.protocol = "Java NIO (OS I/O)"
dfl206.order = 6

# ── DF-L2-07  P2.3 → P2.4 : File metadata + FileHash ────────────────────────
dfl207 = Dataflow(p23, p24, "DF-L2-07: File Metadata + FileHash")
dfl207.description = (
    "P2.3 passes the following to P2.4 for persistence: "
    "  FileId (new UUID), FileName (sanitised original name — display only), "
    "  FolderId, OwnerId, MimeType, Size, PhysicalOsPath (UUID on disk), "
    "  FileHash (SHA-256 of written bytes), UploadedAt (now), IsDeleted=false."
)
dfl207.protocol = "Internal (Spring Boot JVM)"
dfl207.order = 7

# ── DF-L2-08  P2.4 → PostgreSQL : INSERT File + FileVersion ─────────────────
dfl208 = Dataflow(p24, db, "DF-L2-08: INSERT File + FileVersion (JDBC)")
dfl208.description = (
    "P2.4 persists the new File and FileVersion records using prepared "
    "statements (never string concatenation). "
    "INSERT INTO files (file_id, file_name, folder_id, owner_id, is_deleted) "
    "  VALUES (?, ?, ?, ?, false). "
    "INSERT INTO file_versions (version_id, file_id, physical_os_path, size, "
    "  mime_type, file_hash, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?)."
)
dfl208.protocol = "JDBC / TLS"
dfl208.tlsVersion = TLSVersion.TLSv12
dfl208.order = 8

# ── DF-L2-09  P2.4 → P2.5 : Upload audit event ──────────────────────────────
dfl209 = Dataflow(p24, p25, "DF-L2-09: Upload Audit Event")
dfl209.description = (
    "After successful persistence, P2.4 instructs P2.5 to emit an audit event "
    "BEFORE returning the success response to the caller. "
    "Event: { action: 'UPLOAD', userId, resourceId: FileId, "
    "resourceType: 'FILE', sourceIP, outcome: 'SUCCESS', timestamp }."
)
dfl209.protocol = "Internal (Spring Boot JVM)"
dfl209.order = 9

# ── DF-L2-10  P2.5 → ELK/SIEM : Structured audit log ────────────────────────
dfl210 = Dataflow(p25, ext_log, "DF-L2-10: Structured Audit Log (HTTPS/TLS)")
dfl210.description = (
    "P2.5 forwards the JSON audit event to the External Log System over "
    "HTTPS/TLS authenticated with an API key. "
    "This crossing of Trust Boundary C is the key enforcement point for "
    "log immutability and non-repudiation (mitigates T-13). "
    "Logs are never stored exclusively on the local server."
)
dfl210.protocol = "HTTPS/TLS"
dfl210.tlsVersion = TLSVersion.TLSv13
dfl210.order = 10

# ══════════════════════════════════════════════════════════════════════════════
# DOWNLOAD FLOW  (corresponds to Level 1: DF-04, DF-05)
# ══════════════════════════════════════════════════════════════════════════════

# ── DF-L2-11  User → P2.1 : Download request ─────────────────────────────────
dfl211 = Dataflow(user, p21, "DF-L2-11: Download Request (GET /files/{fileId})")
dfl211.description = (
    "Authenticated user requests to download a file by its fileId (UUID). "
    "GET /files/{fileId}. JWT access token in Authorization: Bearer header. "
    "P2.1 validates the fileId format (must be a valid UUID — no path "
    "separators or special characters) before forwarding to P2.2."
)
dfl211.protocol = "HTTPS/TLS"
dfl211.tlsVersion = TLSVersion.TLSv13
dfl211.usesSessionTokens = True
dfl211.order = 11

# ── DF-L2-12  P2.2 → P2.4 : Request FileVersion record ──────────────────────
dfl212 = Dataflow(p22, p24, "DF-L2-12: Request FileVersion + AccessShare")
dfl212.description = (
    "After P2.2 confirms the caller holds at least VIEWER role for the "
    "requested fileId (object-level authorisation — prevents T-07 IDOR), "
    "it requests the FileVersion record from P2.4 to obtain PhysicalOsPath "
    "and FileHash for the file read."
)
dfl212.protocol = "Internal (Spring Boot JVM)"
dfl212.order = 12

# ── DF-L2-13  P2.4 → P2.3 : PhysicalOsPath + FileHash ───────────────────────
dfl213 = Dataflow(p24, p23, "DF-L2-13: PhysicalOsPath + FileHash")
dfl213.description = (
    "P2.4 returns the PhysicalOsPath (UUID filename) and stored FileHash "
    "(SHA-256) from the FileVersion record to P2.3. "
    "P2.3 will use PhysicalOsPath to locate the file on disk and FileHash "
    "to verify integrity after reading."
)
dfl213.protocol = "Internal (Spring Boot JVM)"
dfl213.order = 13

# ── DF-L2-14  File System → P2.3 : Binary file content ──────────────────────
dfl214 = Dataflow(filesystem, p23, "DF-L2-14: Read Binary File (Java NIO)")
dfl214.description = (
    "P2.3 reads the binary file from /srv/files/{uuid} via Java NIO. "
    "Path is normalised and validated against basedir before read. "
    "After reading, P2.3 computes SHA-256(read bytes) and compares to the "
    "stored FileHash. If they differ, P2.3 raises an integrity alert, "
    "logs a DOWNLOAD_INTEGRITY_FAIL audit event via P2.5, and returns "
    "HTTP 500 — the corrupted file is NOT served (RS-NEW-11, mitigates T-17)."
)
dfl214.protocol = "Java NIO (OS I/O)"
dfl214.isResponse = True
dfl214.responseTo = dfl206
dfl214.order = 14

# ── DF-L2-15  P2.3 → User : File download response ───────────────────────────
dfl215 = Dataflow(p23, user, "DF-L2-15: File Download Response (attachment)")
dfl215.description = (
    "P2.3 streams the verified file bytes to the user. "
    "Response headers: "
    "  Content-Disposition: attachment; filename=\"{sanitised_original_name}\" "
    "  Content-Type: {validated_mime_type} "
    "  X-Content-Type-Options: nosniff "
    "Files are NEVER served via a direct static URL — always proxied through "
    "the application so that P2.2 authorisation is always enforced."
)
dfl215.protocol = "HTTPS/TLS"
dfl215.tlsVersion = TLSVersion.TLSv13
dfl215.isResponse = True
dfl215.responseTo = dfl211
dfl215.order = 15

# ══════════════════════════════════════════════════════════════════════════════
# DELETE FLOW  (corresponds to Level 1: DF-06)
# ══════════════════════════════════════════════════════════════════════════════

# ── DF-L2-16  User → P2.1 : Delete request ───────────────────────────────────
dfl216 = Dataflow(user, p21, "DF-L2-16: Delete Request (DELETE /files/{fileId})")
dfl216.description = (
    "Authenticated user requests deletion of a file by its fileId. "
    "DELETE /files/{fileId}. JWT access token in Authorization: Bearer header. "
    "P2.1 validates the fileId format; P2.2 enforces that only OWNER role "
    "may delete — an EDITOR sending this request is rejected with HTTP 403 "
    "(mitigates T-09 role abuse). "
    "Deletion is a soft delete: P2.4 sets IsDeleted=true on the File aggregate. "
    "Physical file removal from the filesystem is handled by a separate "
    "scheduled cleanup process after soft-delete confirmation."
)
dfl216.protocol = "HTTPS/TLS"
dfl216.tlsVersion = TLSVersion.TLSv13
dfl216.usesSessionTokens = True
dfl216.order = 16

# ─────────────────────────────────────────────────────────────────────────────
# PROCESS
# ─────────────────────────────────────────────────────────────────────────────
tm.process()