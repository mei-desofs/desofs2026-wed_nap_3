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

    P2.1  File Request Handler
          Single entry point for all incoming file requests. Combines
          input validation and authorisation into one process:
          — Filename sanitisation and path normalisation (RS-04)
          — MIME-type validation via magic bytes (RS-03, RS-05)
          — File size check against configured limit (RS-05)
          — Rate limiting per user (RS-10)
          — JWT validation: signature, algorithm (HS256/RS256 only,
            reject 'none'), expiry and issuer claims (RS-01, RS-NEW-01)
          — AccessShare resolution: determines caller's RoleType
            (OWNER | EDITOR | VIEWER) for the requested resource
          — Object-level authorisation: confirms the caller has
            permission for the specific resource, not just the endpoint
            (prevents T-07 IDOR)
          — RBAC matrix enforcement: DELETE is OWNER-only, upload
            requires OWNER or EDITOR, download requires any role
            (prevents T-09 role abuse)
          If any check fails the request is rejected immediately with
          a generic error message — no I/O occurs.

    P2.2  File Store (Binary I/O — Java NIO)
          Writes (upload) or reads (download) the binary file on the
          Physical File System via Java NIO.
          — Upload: generates UUID for PhysicalOsPath, normalises and
            validates path against base directory, writes file bytes,
            computes SHA-256 FileHash (RS-NEW-11)
          — Download: retrieves PhysicalOsPath from P2.3, normalises
            and validates path, reads file bytes, verifies SHA-256
            against stored FileHash — aborts if mismatch (T-17)
          — Delete: no physical I/O here; soft delete only via P2.3

    P2.3  Metadata Store (PostgreSQL via JDBC)
          Persists and queries the File and FileVersion domain aggregates
          using prepared statements / JPA named queries only — string
          concatenation in SQL is prohibited (prevents T-11).
          — Upload: INSERT File + FileVersion records including FileHash
          — Download: SELECT FileVersion to retrieve PhysicalOsPath
            and FileHash for integrity verification
          — Delete: UPDATE files SET IsDeleted=true (soft delete only)
          — StorageQuota check on upload (RS-NEW-07)
          — AccessShare lookup called by P2.1 for authorisation
          DB user has DML-only permissions (RS-NEW-06).

    P2.4  Audit Log Service
          Emits a structured JSON audit event for every File Service
          operation BEFORE returning a response to the caller.
          Forwards events to the External Log System (ELK/SIEM) over
          HTTPS/TLS authenticated via API key (RS-NEW-03).
          Logs are never stored exclusively on the local server.
          Sensitive data is never logged (RNF-04).

Threat mapping (from threat model Section 8):
  P2.1 File Request Handler ← T-05 Path Traversal
                               T-06 Malicious File Upload (Web Shell / RCE)
                               T-07 IDOR (missing object-level auth check)
                               T-08 DoS by Upload (file size / rate limit)
                               T-09 Role Abuse (Editor performs delete)
  P2.2 File Store           ← T-05 Path Traversal (base-dir escape on I/O)
                               T-17 File Integrity Tampering on Disk
  P2.3 Metadata Store       ← T-11 SQL Injection (unparameterised queries)
                               T-12 Sensitive Data in Logs / Errors
  P2.4 Audit Log Service    ← T-13 Repudiation (absence of audit trail)

Trust Boundaries at Level 2:
  boundary_a   — Internet / Application:
                 The calling User (browser/app) lives here. All data
                 crossing this boundary is untrusted and must pass the
                 File Request Handler (P2.1) before touching any data store.
  boundary_b   — Application / Infrastructure:
                 PostgreSQL and the Physical File System live here.
                 Only P2.2 and P2.3 (running inside the Spring Boot JVM)
                 may cross this boundary.
  boundary_c   — Application / External Log System:
                 The ELK/SIEM lives here. P2.4 crosses this boundary
                 outbound with structured JSON audit events over
                 HTTPS/TLS authenticated via API key.

DFD Notation (T3 slides):
  Actor      → External Entity  (rectangle)
  Server     → Process          (circle / ellipse)
  Datastore  → Data Store       (two parallel lines)
  Boundary   → Trust Boundary   (dashed line)
  Dataflow   → Data Flow        (arrow)

Data flow numbering:
  Flows DF-L2-01 … DF-L2-15 are internal to the File Service.
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
    "monolith. Shows four internal sub-processes: File Request Handler "
    "(input validation + authorisation combined), File Store, Metadata Store, "
    "and Audit Log Service, with trust boundaries separating the untrusted "
    "caller from the application logic and the infrastructure data stores."
)
tm.isOrdered = True
tm.mergeResponses = True

# ─────────────────────────────────────────────────────────────────────────────
# TRUST BOUNDARIES
# ─────────────────────────────────────────────────────────────────────────────

# Boundary A — Internet / Application
# The calling User originates from the untrusted internet. All request data
# (file content, filename, JWT, headers) crosses this boundary and must be
# treated as untrusted until validated and authorised by the File Request
# Handler (P2.1).
boundary_a = Boundary("Trust Boundary A — Internet / Application")

# Boundary B — Application / Infrastructure
# Separates the Spring Boot JVM (where P2.1–P2.4 execute) from the
# infrastructure data stores: PostgreSQL and the Physical File System.
# Only the application process account may access these stores.
# PostgreSQL is accessed via JDBC with a DML-only DB user.
# The filesystem directory is outside the web root with no execute permissions.
boundary_b = Boundary("Trust Boundary B — Application / Infrastructure")

# Boundary C — Application / External Log System
# The ELK/SIEM log aggregation system lives here. Structured JSON audit events
# cross this boundary outbound from P2.4 over HTTPS/TLS with API-key auth.
# This boundary exists to make the log forwarding crossing explicit in the DFD
# and is the key enforcement point for log immutability and non-repudiation.
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
    "Untrusted — all input must be validated and authorised by the "
    "File Request Handler (P2.1) before any I/O occurs."
)
user.inBoundary = boundary_a

ext_log = Actor("External Log System (ELK / SIEM)")
ext_log.description = (
    "External log aggregation system that receives structured JSON audit "
    "events from the Audit Log Service (P2.4) in real time. "
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

p21 = Server("P2.1 File Request Handler")
p21.description = (
    "Single entry point for all incoming file requests. Combines input "
    "validation and authorisation into one process before any I/O occurs. "
    "Input validation: "
    "(1) Filename sanitisation: strip directory separators, null bytes and "
    "    control characters from the user-supplied filename. "
    "(2) Path normalisation: resolve candidate path with "
    "    java.nio.file.Path.normalize() and verify it stays inside the "
    "    configured base directory (prevents T-05 Path Traversal). "
    "(3) MIME-type validation: read magic bytes via Apache Tika — never "
    "    trust the Content-Type header sent by the client "
    "    (prevents T-06 Web Shell upload). "
    "(4) File size check: reject uploads exceeding the configured maximum "
    "    before any write occurs (mitigates T-08 DoS by upload). "
    "(5) Rate limiting: enforce per-user upload rate; return HTTP 429 "
    "    if exceeded (RS-10). "
    "Authorisation: "
    "(6) JWT validation: verify signature, algorithm (HS256/RS256 only — "
    "    reject 'none'), expiry and issuer claims (RS-01, RS-NEW-01). "
    "(7) AccessShare resolution: query PostgreSQL to determine the caller's "
    "    RoleType (OWNER | EDITOR | VIEWER) for the requested resource. "
    "(8) RBAC matrix: OWNER — all ops; EDITOR — upload/download; "
    "    VIEWER — download only. DELETE is OWNER-only "
    "    (prevents T-09 role abuse). "
    "(9) Object-level check: confirm the caller has AccessShare permission "
    "    for the specific resourceId, not just that they are authenticated "
    "    (prevents T-07 IDOR). "
    "If any check fails: reject with generic HTTP 403/429 — no I/O occurs "
    "and no sensitive detail is disclosed in the response."
)
p21.protocol = "HTTPS/TLS"
p21.tlsVersion = TLSVersion.TLSv13
p21.usesSessionTokens = True
p21.inBoundary = boundary_a

p22 = Server("P2.2 File Store (Java NIO / OS I/O)")
p22.description = (
    "Handles binary file I/O on the Physical File System via Java NIO. "
    "Upload path: "
    "(1) Generate a new UUID for this FileVersion (PhysicalOsPath). "
    "    The user-supplied original filename is NEVER used as a path "
    "    component — it is stored only as metadata in PostgreSQL. "
    "(2) Resolve full path: basedir + '/' + UUID. Normalise and verify "
    "    the resolved path is still inside basedir (defence-in-depth "
    "    against T-05, even though P2.1 already validated the input). "
    "(3) Write file bytes via Files.write() or a streaming channel. "
    "(4) Compute SHA-256 hash of the written bytes — passed to P2.3 for "
    "    storage as FileVersion.FileHash (supports T-17 integrity check). "
    "Download path: "
    "(1) Retrieve PhysicalOsPath from FileVersion record (supplied by P2.3). "
    "(2) Normalise and validate path against basedir. "
    "(3) Read file bytes via Files.readAllBytes() or a streaming channel. "
    "(4) Verify SHA-256 hash against stored FileVersion.FileHash — raise "
    "    integrity alert and abort if mismatch (RS-NEW-11, mitigates T-17). "
    "Delete path: "
    "    No physical file removal here. The File aggregate IsDeleted flag "
    "    is set to true by P2.3 (soft delete). Physical removal is handled "
    "    by a separate scheduled cleanup process — preventing data loss."
)
p22.protocol = "Java NIO (OS I/O)"
p22.inBoundary = boundary_b

p23 = Server("P2.3 Metadata Store (JDBC / PostgreSQL)")
p23.description = (
    "Persists and queries the File and FileVersion domain aggregates in "
    "PostgreSQL using prepared statements / JPA named queries only. "
    "String concatenation in SQL is prohibited (prevents T-11 SQL injection). "
    "Upload: INSERT into files and file_versions tables. "
    "    Stored fields: FileId (UUID), FileName (sanitised original name — "
    "    display only), OwnerId, FolderId, MimeType, Size, "
    "    PhysicalOsPath (UUID filename), FileHash (SHA-256 from P2.2), "
    "    UploadedAt, IsDeleted=false. "
    "Download: SELECT FileVersion record to retrieve PhysicalOsPath and "
    "    FileHash — supplied to P2.2 for the actual file read and integrity "
    "    verification. "
    "Delete: UPDATE files SET IsDeleted=true WHERE FileId=? — soft delete "
    "    only; physical file remains on disk until cleanup. "
    "StorageQuota check (upload): SELECT SUM(size) FROM file_versions WHERE "
    "    OwnerId=? — reject with HTTP 429 if quota would be exceeded "
    "    (RS-NEW-07). "
    "AccessShare lookup (called by P2.1): SELECT role_type FROM access_share "
    "    WHERE resource_id=? AND granted_to_user_id=? "
    "    Used for object-level authorisation before any I/O. "
    "DB user has DML-only permissions: SELECT, INSERT, UPDATE, DELETE. "
    "No DDL or administrative privileges (RS-NEW-06)."
)
p23.protocol = "JDBC / TLS"
p23.tlsVersion = TLSVersion.TLSv12
p23.inBoundary = boundary_b

p24 = Server("P2.4 Audit Log Service")
p24.description = (
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
    "(RNF-04). Generic error messages used for failureReason to avoid "
    "disclosing internal system details (RS-09)."
)
p24.protocol = "HTTPS/TLS"
p24.tlsVersion = TLSVersion.TLSv13
p24.inBoundary = boundary_a

# ─────────────────────────────────────────────────────────────────────────────
# DATA STORES  —  Datastore (two parallel lines in DFD)
# ─────────────────────────────────────────────────────────────────────────────

db = Datastore("PostgreSQL Database")
db.description = (
    "Stores the File and FileVersion domain aggregates and the AccessShare "
    "records queried by the File Request Handler (P2.1) for authorisation. "
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
    "Stores binary file content named with system-generated UUIDs "
    "(FileVersion.PhysicalOsPath) — the user-supplied original filename is "
    "never present on disk. "
    "Directory permissions: readable and writable by the Spring Boot process "
    "OS user only. No execute permissions on the directory or its contents. "
    "Accessed by P2.2 via Java NIO (Files.write / Files.readAllBytes). "
    "Physical file removal happens only via a scheduled cleanup process "
    "after IsDeleted=true has been confirmed in PostgreSQL."
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

# ── DF-L2-01  User → P2.1 : Upload request ───────────────────────────────────
dfl201 = Dataflow(user, p21, "DF-L2-01: Upload Request (POST /files/upload)")
dfl201.description = (
    "Authenticated user sends POST /files/upload with a multipart/form-data "
    "body containing: file binary content, original filename, target folderId. "
    "JWT access token in Authorization: Bearer header. "
    "All data is untrusted at this point — P2.1 validates and authorises "
    "before any I/O occurs."
)
dfl201.protocol = "HTTPS/TLS"
dfl201.tlsVersion = TLSVersion.TLSv13
dfl201.usesSessionTokens = True
dfl201.order = 1

# ── DF-L2-02  P2.1 → PostgreSQL : AccessShare + StorageQuota lookup ──────────
dfl202 = Dataflow(p21, db, "DF-L2-02: AccessShare + StorageQuota Lookup (JDBC)")
dfl202.description = (
    "The File Request Handler queries PostgreSQL to resolve the caller's "
    "RoleType for the target resource and to check the StorageQuota. "
    "Query 1 — AccessShare (prepared statement): "
    "  SELECT role_type FROM access_share "
    "  WHERE resource_id=? AND granted_to_user_id=? "
    "  AND resource_type='FOLDER'. "
    "Query 2 — StorageQuota (prepared statement): "
    "  SELECT SUM(fv.size) FROM file_versions fv "
    "  JOIN files f ON fv.file_id=f.file_id WHERE f.owner_id=?."
)
dfl202.protocol = "JDBC / TLS"
dfl202.tlsVersion = TLSVersion.TLSv12
dfl202.order = 2

# ── DF-L2-03  PostgreSQL → P2.1 : AccessShare + quota result ─────────────────
dfl203 = Dataflow(db, p21, "DF-L2-03: AccessShare + Quota Result (JDBC)")
dfl203.description = (
    "PostgreSQL returns the caller's RoleType and current storage used. "
    "If role is VIEWER or record does not exist: P2.1 rejects with HTTP 403. "
    "If quota would be exceeded: P2.1 rejects with HTTP 429. "
    "If both pass: P2.1 forwards the validated request to P2.2."
)
dfl203.protocol = "JDBC / TLS"
dfl203.tlsVersion = TLSVersion.TLSv12
dfl203.isResponse = True
dfl203.responseTo = dfl202
dfl203.order = 3

# ── DF-L2-04  P2.1 → P2.2 : Validated + authorised upload ───────────────────
dfl204 = Dataflow(p21, p22, "DF-L2-04: Validated Upload — File Bytes")
dfl204.description = (
    "After all validation and authorisation checks pass in P2.1, the "
    "validated file bytes and sanitised metadata are forwarded to P2.2 "
    "for physical storage. A new UUID is generated for PhysicalOsPath. "
    "Data: validated file bytes, sanitised filename, folderId, OwnerId, "
    "validated MimeType, file size."
)
dfl204.protocol = "Internal (Spring Boot JVM)"
dfl204.order = 4

# ── DF-L2-05  P2.2 → File System : Write binary file ────────────────────────
dfl205 = Dataflow(p22, filesystem, "DF-L2-05: Write Binary File (Java NIO)")
dfl205.description = (
    "P2.2 writes the file bytes to /srv/files/{uuid} via Java NIO. "
    "The UUID filename (PhysicalOsPath) is generated by the application — "
    "the user-supplied original filename is never part of the path. "
    "Path is normalised and verified to be inside the base directory. "
    "After writing, P2.2 computes SHA-256(file bytes) → FileHash."
)
dfl205.protocol = "Java NIO (OS I/O)"
dfl205.order = 5

# ── DF-L2-06  P2.2 → P2.3 : File metadata + FileHash ────────────────────────
dfl206 = Dataflow(p22, p23, "DF-L2-06: File Metadata + FileHash")
dfl206.description = (
    "P2.2 passes the following to P2.3 for persistence: "
    "  FileId (new UUID), FileName (sanitised original name — display only), "
    "  FolderId, OwnerId, MimeType, Size, PhysicalOsPath (UUID on disk), "
    "  FileHash (SHA-256 of written bytes), UploadedAt (now), IsDeleted=false."
)
dfl206.protocol = "Internal (Spring Boot JVM)"
dfl206.order = 6

# ── DF-L2-07  P2.3 → PostgreSQL : INSERT File + FileVersion ─────────────────
dfl207 = Dataflow(p23, db, "DF-L2-07: INSERT File + FileVersion (JDBC)")
dfl207.description = (
    "P2.3 persists the new File and FileVersion records using prepared "
    "statements — never string concatenation (prevents T-11). "
    "INSERT INTO files (file_id, file_name, folder_id, owner_id, is_deleted) "
    "  VALUES (?, ?, ?, ?, false). "
    "INSERT INTO file_versions (version_id, file_id, physical_os_path, size, "
    "  mime_type, file_hash, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?)."
)
dfl207.protocol = "JDBC / TLS"
dfl207.tlsVersion = TLSVersion.TLSv12
dfl207.order = 7

# ── DF-L2-08  P2.3 → P2.4 : Upload audit event ──────────────────────────────
dfl208 = Dataflow(p23, p24, "DF-L2-08: Upload Audit Event")
dfl208.description = (
    "After successful persistence, P2.3 instructs P2.4 to emit an audit "
    "event BEFORE returning the success response to the caller. "
    "Event: { action: 'UPLOAD', userId, resourceId: FileId, "
    "resourceType: 'FILE', sourceIP, outcome: 'SUCCESS', timestamp }."
)
dfl208.protocol = "Internal (Spring Boot JVM)"
dfl208.order = 8

# ── DF-L2-09  P2.4 → ELK/SIEM : Structured audit log ────────────────────────
dfl209 = Dataflow(p24, ext_log, "DF-L2-09: Structured Audit Log (HTTPS/TLS)")
dfl209.description = (
    "P2.4 forwards the JSON audit event to the External Log System over "
    "HTTPS/TLS authenticated with an API key. "
    "Crossing Trust Boundary C — key enforcement point for log immutability "
    "and non-repudiation (mitigates T-13). "
    "Logs are never stored exclusively on the local server."
)
dfl209.protocol = "HTTPS/TLS"
dfl209.tlsVersion = TLSVersion.TLSv13
dfl209.order = 9

# ══════════════════════════════════════════════════════════════════════════════
# DOWNLOAD FLOW  (corresponds to Level 1: DF-04, DF-05)
# ══════════════════════════════════════════════════════════════════════════════

# ── DF-L2-10  User → P2.1 : Download request ─────────────────────────────────
dfl210 = Dataflow(user, p21, "DF-L2-10: Download Request (GET /files/{fileId})")
dfl210.description = (
    "Authenticated user requests a file by its fileId (UUID). "
    "GET /files/{fileId}. JWT access token in Authorization: Bearer header. "
    "P2.1 validates the fileId format, validates the JWT, and confirms the "
    "caller holds at least VIEWER role for this fileId via AccessShare "
    "(object-level authorisation — prevents T-07 IDOR)."
)
dfl210.protocol = "HTTPS/TLS"
dfl210.tlsVersion = TLSVersion.TLSv13
dfl210.usesSessionTokens = True
dfl210.order = 10

# ── DF-L2-11  P2.1 → P2.3 : Request FileVersion record ──────────────────────
dfl211 = Dataflow(p21, p23, "DF-L2-11: Request FileVersion (PhysicalOsPath + FileHash)")
dfl211.description = (
    "After P2.1 confirms the caller is authorised, it requests the "
    "FileVersion record from P2.3 to obtain PhysicalOsPath and FileHash "
    "needed for the physical file read and integrity verification."
)
dfl211.protocol = "Internal (Spring Boot JVM)"
dfl211.order = 11

# ── DF-L2-12  P2.3 → P2.2 : PhysicalOsPath + FileHash ───────────────────────
dfl212 = Dataflow(p23, p22, "DF-L2-12: PhysicalOsPath + FileHash")
dfl212.description = (
    "P2.3 returns the PhysicalOsPath (UUID filename on disk) and stored "
    "FileHash (SHA-256) from the FileVersion record. "
    "P2.2 uses PhysicalOsPath to locate the file and FileHash to verify "
    "integrity after reading."
)
dfl212.protocol = "Internal (Spring Boot JVM)"
dfl212.order = 12

# ── DF-L2-13  File System → P2.2 : Binary file content ──────────────────────
dfl213 = Dataflow(filesystem, p22, "DF-L2-13: Read Binary File (Java NIO)")
dfl213.description = (
    "P2.2 reads the binary file from /srv/files/{uuid} via Java NIO. "
    "Path is normalised and validated against basedir before read. "
    "After reading, P2.2 computes SHA-256(read bytes) and compares to the "
    "stored FileHash. If they differ: P2.2 raises an integrity alert, "
    "instructs P2.4 to log DOWNLOAD_INTEGRITY_FAIL, and returns HTTP 500 — "
    "the corrupted file is NOT served (RS-NEW-11, mitigates T-17)."
)
dfl213.protocol = "Java NIO (OS I/O)"
dfl213.isResponse = True
dfl213.responseTo = dfl205
dfl213.order = 13

# ── DF-L2-14  P2.2 → User : File download response ───────────────────────────
dfl214 = Dataflow(p22, user, "DF-L2-14: File Download Response (attachment)")
dfl214.description = (
    "P2.2 streams the integrity-verified file bytes to the user. "
    "Response headers: "
    "  Content-Disposition: attachment; filename=\"{sanitised_original_name}\" "
    "  Content-Type: {validated_mime_type} "
    "  X-Content-Type-Options: nosniff "
    "Files are NEVER served via a direct static URL — always proxied through "
    "the application so that P2.1 authorisation is always enforced."
)
dfl214.protocol = "HTTPS/TLS"
dfl214.tlsVersion = TLSVersion.TLSv13
dfl214.isResponse = True
dfl214.responseTo = dfl210
dfl214.order = 14

# ══════════════════════════════════════════════════════════════════════════════
# DELETE FLOW  (corresponds to Level 1: DF-06)
# ══════════════════════════════════════════════════════════════════════════════

# ── DF-L2-15  User → P2.1 : Delete request ───────────────────────────────────
dfl215 = Dataflow(user, p21, "DF-L2-15: Delete Request (DELETE /files/{fileId})")
dfl215.description = (
    "Authenticated user requests deletion of a file by its fileId. "
    "DELETE /files/{fileId}. JWT access token in Authorization: Bearer header. "
    "P2.1 validates the fileId format and JWT, then enforces that only OWNER "
    "role may delete — an EDITOR or VIEWER is rejected with HTTP 403 "
    "(mitigates T-09 role abuse). "
    "P2.1 then instructs P2.3 to soft delete: "
    "UPDATE files SET IsDeleted=true WHERE FileId=?. "
    "Physical file removal is handled by a separate scheduled cleanup process."
)
dfl215.protocol = "HTTPS/TLS"
dfl215.tlsVersion = TLSVersion.TLSv13
dfl215.usesSessionTokens = True
dfl215.order = 15

# ─────────────────────────────────────────────────────────────────────────────
# PROCESS
# ─────────────────────────────────────────────────────────────────────────────
tm.process()