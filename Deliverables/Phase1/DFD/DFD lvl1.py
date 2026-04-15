#!/usr/bin/env python3
"""
DESOFS 2025/2026 — Secure File Management System
Phase 1 — Threat Modeling: Data Flow Diagrams (pytm)

Elemento 2

Architecture (from Image 1 — Component Diagram):
  - Single Spring Boot Application (monolith, NOT microservices)
  - Browser/App  --HTTPS-->  Spring Boot App
  - Spring Boot  --JDBC-->   PostgreSQL  (stores metadata, UUIDs, roles)
  - Spring Boot  --Java NIO (OS I/O)-->  Physical File System
                                          (binary files named with UUIDs)

Domain Model (from Image 2 — DDD Aggregate Diagram):
  Aggregate Roots:
    User          — UserId (UUID), Username, Email, PasswordHash,
                    StorageQuota, IsLocked
    File          — FileId (UUID), FileName, FolderId, OwnerId,
                    IsDeleted (soft delete)
    FileVersion   — VersionId, FileId, PhysicalOsPath, Size, MimeType,
                    FileHash (integrity), UploadedAt
    Folder        — FolderId (UUID), FolderName, OwnerId, ParentFolderId
    AccessShare   — ShareId (UUID), ResourceId, ResourceType (FILE|FOLDER),
                    GrantedToUserId, RoleType (OWNER|EDITOR|VIEWER)
  Notes:
    - AccessShare enforces RBAC / Least Privilege, evaluated before any
      OS-level I/O.
    - Soft delete on File prevents immediate data loss.
    - FileHash on FileVersion fulfils SSDLC 'Repair the damage' (integrity).
    - StorageQuota on User enforces per-user upload limits.
    - IsLocked on User supports account lockout after failed auth.

Trust Boundaries:
  boundary_a       — Internet / Application  (User + Spring Boot App)
  boundary_a_admin — Internet / Application  (Administrator — separate object
                     so Threat Dragon renders it inside an explicit boundary
                     box, making it clear admin traffic is also untrusted
                     internet traffic subject to JWT auth and TLS)
  boundary_b       — Application / Infrastructure  (PostgreSQL + File System)
  boundary_c       — Application / External Log System  (ELK / SIEM)
                     DF-14 crosses from boundary_a → boundary_c, which is
                     the key trust boundary crossing for audit log forwarding.

DFD Notation (T3 slides):
  Actor      → External Entity  (rectangle)
  Server     → Process          (circle / ellipse)
  Datastore  → Data Store       (two parallel lines)
  Boundary   → Trust Boundary   (dashed line)
  Dataflow   → Data Flow        (arrow)

Run:
  python3 dfd.py --dfd | dot -Tpng -o dfd_level1.png
  python3 dfd.py --dfd | dot -Tsvg -o dfd_level1.svg
  python3 dfd.py --seq | dot -Tpng -o seq.png
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
tm = TM("Secure File Management System")
tm.description = (
    "A Spring Boot REST API (monolith) that allows authenticated users to "
    "upload, download, organise and share files. RBAC is enforced via the "
    "AccessShare aggregate (OWNER / EDITOR / VIEWER) evaluated before any "
    "OS-level I/O. Files are stored on the Physical File System using UUID "
    "filenames (Java NIO). Metadata, UUIDs and roles are persisted in "
    "PostgreSQL (JDBC). All communication is over HTTPS/TLS."
)
tm.isOrdered = True
tm.mergeResponses = True

# ─────────────────────────────────────────────────────────────────────────────
# TRUST BOUNDARIES
# ─────────────────────────────────────────────────────────────────────────────

# Boundary A — Internet / Application
# Separates untrusted external actors (browser) from the Spring Boot
# application. All data crossing here must be authenticated (JWT) and
# validated (input sanitisation, path normalisation, magic-byte file check).
boundary_a = Boundary("Trust Boundary A — Internet / Application")

# Boundary A (Admin) — same logical boundary as A but kept as a separate
# Boundary object so Threat Dragon renders the Administrator rectangle visibly
# inside a trust boundary box, making it explicit that admin traffic also
# crosses the Internet/Application boundary and is subject to the same
# JWT authentication and TLS requirements.
boundary_a_admin = Boundary("Trust Boundary A — Internet / Application (Admin)")

# Boundary B — Application / Infrastructure
# Separates the Spring Boot process from the internal data stores
# (PostgreSQL and Physical File System). Only the application process may
# access these stores. PostgreSQL accessed via JDBC with a DML-only user.
# File System accessed via Java NIO; directory is outside the web root.
boundary_b = Boundary("Trust Boundary B — Application / Infrastructure")

# Boundary C — Application / External Log System
# Audit logs are forwarded outbound from the Spring Boot application (inside
# Boundary A) to the External Log System (inside Boundary C) over HTTPS/TLS.
# DF-14 crosses this boundary — making it visible in the DFD is the primary
# reason this boundary exists. The crossing point is where log integrity and
# confidentiality must be enforced (TLS + API key authentication).
boundary_c = Boundary("Trust Boundary C — Application / External Log System")

# ─────────────────────────────────────────────────────────────────────────────
# EXTERNAL ENTITIES  —  Actor (rectangle in DFD)
# ─────────────────────────────────────────────────────────────────────────────

user = Actor("User (Browser / App)")
user.description = (
    "An end user interacting with the system via a browser or mobile REST "
    "client. May hold the role OWNER, EDITOR or VIEWER on a given resource "
    "(File or Folder), as determined by the AccessShare aggregate. "
    "Account is subject to StorageQuota enforcement and IsLocked lockout."
)
user.inBoundary = boundary_a

admin = Actor("Administrator")
admin.description = (
    "A privileged user who manages user accounts (create, suspend, delete) "
    "and system configuration via administrative endpoints. "
    "Authenticated by JWT carrying the Admin role."
)
admin.inBoundary = boundary_a_admin
admin.isAdmin = True

ext_log = Actor("External Log System (ELK / SIEM)")
ext_log.description = (
    "External log aggregation system that receives structured JSON audit "
    "events from the Spring Boot application in real time. "
    "Write-only, authenticated via API key over HTTPS/TLS. "
    "Provides immutable audit trail for non-repudiation."
)
ext_log.inBoundary = boundary_c

# ─────────────────────────────────────────────────────────────────────────────
# PROCESS  —  Server (circle / ellipse in DFD)
# Single Spring Boot monolith — one process, not microservices.
# Internally handles: authentication, file ops, folder ops, access control,
# audit logging and OS-level I/O via Java NIO.
# ─────────────────────────────────────────────────────────────────────────────

app = Server("Spring Boot Application")
app.description = (
    "Single Spring Boot monolith exposing a REST API over HTTPS/TLS. "
    "Internally handles: "
    "(1) Authentication — JWT issuance (15 min access token + refresh token), "
    "BCrypt/Argon2 password hashing, rate limiting, account lockout (IsLocked). "
    "(2) File operations — upload (magic-byte validation, UUID rename, "
    "StorageQuota check), download (Content-Disposition: attachment), "
    "soft delete (IsDeleted), FileHash integrity verification. "
    "(3) Folder operations — create/rename/delete via Java NIO (OS I/O), "
    "path normalisation to prevent path traversal. "
    "(4) Access control — AccessShare evaluated before every OS-level I/O; "
    "RBAC matrix: OWNER / EDITOR / VIEWER x CRUD x Share x Revoke. "
    "(5) Audit logging — structured JSON events (timestamp, userId, action, "
    "resourceId, sourceIP) forwarded to external ELK/SIEM."
)
app.protocol = "HTTPS/TLS"
app.port = 443
app.tlsVersion = TLSVersion.TLSv13
app.usesSessionTokens = True
app.inBoundary = boundary_a

# ─────────────────────────────────────────────────────────────────────────────
# DATA STORES  —  Datastore (two parallel lines in DFD)
# ─────────────────────────────────────────────────────────────────────────────

db = Datastore("PostgreSQL Database")
db.description = (
    "Relational database storing the domain model aggregates: "
    "User (UserId, Username, Email, PasswordHash, StorageQuota, IsLocked), "
    "File (FileId, FileName, FolderId, OwnerId, IsDeleted), "
    "FileVersion (VersionId, FileId, PhysicalOsPath, Size, MimeType, "
    "FileHash, UploadedAt), "
    "Folder (FolderId, FolderName, OwnerId, ParentFolderId), "
    "AccessShare (ShareId, ResourceId, ResourceType, GrantedToUserId, "
    "RoleType). "
    "Accessed exclusively via JDBC with prepared statements / JPA named "
    "queries. Production DB user has DML-only permissions (no DDL)."
)
db.isEncrypted = True
db.isSQL = True
db.inBoundary = boundary_b

filesystem = Datastore("Physical File System")
filesystem.description = (
    "Server filesystem directory outside the web root. "
    "Stores binary files referenced by PhysicalOsPath from FileVersion. "
    "Files are named using generated UUIDs (never the original user-supplied "
    "filename) to prevent path traversal. "
    "Directory has no execute permissions. "
    "Accessed by the Spring Boot application via Java NIO (OS I/O). "
    "Only the application process OS user may read/write this directory."
)
filesystem.isEncrypted = False
filesystem.inBoundary = boundary_b

# ─────────────────────────────────────────────────────────────────────────────
# DATA FLOWS  —  Dataflow (arrow in DFD)
# Numbered to match the DF-XX identifiers in the Threat Modeling report.
# ─────────────────────────────────────────────────────────────────────────────

# ── DF-01  User → App : Authentication (login / register / refresh) ──────────
df01 = Dataflow(user, app, "DF-01: Authentication Request")
df01.description = (
    "User submits credentials to register or log in, or exchanges a refresh "
    "token for a new access token. "
    "Endpoints: POST /auth/register | POST /auth/login | POST /auth/refresh. "
    "Rate limited; account locked (IsLocked=true) after repeated failures."
)
df01.protocol = "HTTPS/TLS"
df01.tlsVersion = TLSVersion.TLSv13
df01.order = 1

# ── DF-02  App → User : JWT token response ───────────────────────────────────
df02 = Dataflow(app, user, "DF-02: JWT Token Response")
df02.description = (
    "On successful authentication the application returns a short-lived JWT "
    "access token (15 min expiry) and a refresh token. "
    "Tokens transmitted only over HTTPS/TLS."
)
df02.protocol = "HTTPS/TLS"
df02.tlsVersion = TLSVersion.TLSv13
df02.isResponse = True
df02.responseTo = df01
df02.usesSessionTokens = True
df02.order = 2

# ── DF-03  User → App : File upload ─────────────────────────────────────────
df03 = Dataflow(user, app, "DF-03: File Upload Request")
df03.description = (
    "Authenticated user (OWNER or EDITOR role via AccessShare) uploads a "
    "file. POST /files/upload — multipart/form-data. "
    "JWT in Authorization header. "
    "Application validates: JWT, AccessShare role, file type via magic bytes "
    "(not Content-Type header), file size vs StorageQuota, "
    "then stores binary with UUID name on filesystem and metadata in DB "
    "(File + FileVersion aggregates including FileHash for integrity)."
)
df03.protocol = "HTTPS/TLS"
df03.tlsVersion = TLSVersion.TLSv13
df03.usesSessionTokens = True
df03.order = 3

# ── DF-04  User → App : File download ───────────────────────────────────────
df04 = Dataflow(user, app, "DF-04: File Download Request")
df04.description = (
    "Authenticated user requests a file they have access to. "
    "GET /files/{fileId}. JWT in Authorization header. "
    "Application checks AccessShare before reading PhysicalOsPath from "
    "FileVersion and streaming the file with Content-Disposition: attachment."
)
df04.protocol = "HTTPS/TLS"
df04.tlsVersion = TLSVersion.TLSv13
df04.usesSessionTokens = True
df04.order = 4

# ── DF-05  App → User : File download response ───────────────────────────────
df05 = Dataflow(app, user, "DF-05: File Download Response")
df05.description = (
    "File binary content streamed to the user. "
    "Header: Content-Disposition: attachment. "
    "Never served via a direct static URL — always proxied through the "
    "application so that AccessShare is enforced."
)
df05.protocol = "HTTPS/TLS"
df05.tlsVersion = TLSVersion.TLSv13
df05.isResponse = True
df05.responseTo = df04
df05.order = 5

# ── DF-06  User → App : File delete ──────────────────────────────────────────
df06 = Dataflow(user, app, "DF-06: File Delete Request")
df06.description = (
    "Authenticated OWNER requests deletion of their file. "
    "DELETE /files/{fileId}. "
    "Application performs a soft delete (IsDeleted=true on File aggregate) "
    "to prevent immediate data loss, then logs the action."
)
df06.protocol = "HTTPS/TLS"
df06.tlsVersion = TLSVersion.TLSv13
df06.usesSessionTokens = True
df06.order = 6

# ── DF-07  User → App : Share / revoke access ────────────────────────────────
df07 = Dataflow(user, app, "DF-07: Share / Revoke Access Request")
df07.description = (
    "OWNER grants or revokes access to a File or Folder for another user, "
    "assigning a RoleType (EDITOR or VIEWER) in the AccessShare aggregate. "
    "POST /resources/{resourceId}/share  |  DELETE /resources/{resourceId}/share. "
    "ResourceType determines whether the target is FILE or FOLDER."
)
df07.protocol = "HTTPS/TLS"
df07.tlsVersion = TLSVersion.TLSv13
df07.usesSessionTokens = True
df07.order = 7

# ── DF-08  User → App : Folder operations ────────────────────────────────────
df08 = Dataflow(user, app, "DF-08: Folder Operation Request")
df08.description = (
    "Authenticated user (OWNER or EDITOR) creates, lists, renames or deletes "
    "a folder. POST/GET/PUT/DELETE /folders/{folderId}. "
    "Application normalises all paths via Java NIO to prevent path traversal, "
    "and checks AccessShare before any OS-level directory operation."
)
df08.protocol = "HTTPS/TLS"
df08.tlsVersion = TLSVersion.TLSv13
df08.usesSessionTokens = True
df08.order = 8

# ── DF-09  Admin → App : Administrative operations ───────────────────────────
df09 = Dataflow(admin, app, "DF-09: Admin — User Management Request")
df09.description = (
    "Administrator manages user accounts: create, suspend (IsLocked=true), "
    "or delete. GET/POST/DELETE /admin/users. "
    "Requires JWT with Admin role. Spring Boot Actuator restricted to "
    "internal network only in production."
)
df09.protocol = "HTTPS/TLS"
df09.tlsVersion = TLSVersion.TLSv13
df09.usesSessionTokens = True
df09.order = 9

# ── DF-10  App → PostgreSQL : Read / Write domain data (JDBC) ────────────────
df10 = Dataflow(app, db, "DF-10: Domain Data Read / Write (JDBC)")
df10.description = (
    "Spring Boot application reads and writes all domain aggregates to "
    "PostgreSQL via JDBC using prepared statements / JPA named queries "
    "(never raw string concatenation). "
    "Includes: User credentials (PasswordHash), File & FileVersion metadata "
    "(FileHash, PhysicalOsPath), Folder structure, AccessShare RBAC records. "
    "DB user has DML-only permissions (SELECT, INSERT, UPDATE, DELETE — "
    "no DDL, no TRUNCATE)."
)
df10.protocol = "JDBC / TLS"
df10.tlsVersion = TLSVersion.TLSv12
df10.order = 10

# ── DF-11  PostgreSQL → App : Query results ───────────────────────────────────
df11 = Dataflow(db, app, "DF-11: Domain Data Query Results (JDBC)")
df11.description = (
    "PostgreSQL returns query results to the Spring Boot application: "
    "user records, file/folder metadata, FileVersion entries (including "
    "PhysicalOsPath used for OS I/O), and AccessShare records used to "
    "enforce RBAC before any file or folder operation."
)
df11.protocol = "JDBC / TLS"
df11.tlsVersion = TLSVersion.TLSv12
df11.isResponse = True
df11.responseTo = df10
df11.order = 11

# ── DF-12  App → File System : Write binary file (Java NIO) ──────────────────
df12 = Dataflow(app, filesystem, "DF-12: Write Binary File (Java NIO / OS I/O)")
df12.description = (
    "Spring Boot application writes uploaded binary file to the Physical File "
    "System via Java NIO. "
    "Filename = generated UUID (from FileVersion.PhysicalOsPath) — the "
    "original user-supplied filename is never used as a path component. "
    "Destination directory is outside the web root and has no execute "
    "permissions. Path is normalised and validated against the base directory "
    "before write to prevent path traversal."
)
df12.protocol = "Java NIO (OS I/O)"
df12.order = 12

# ── DF-13  File System → App : Read binary file (Java NIO) ───────────────────
df13 = Dataflow(filesystem, app, "DF-13: Read Binary File (Java NIO / OS I/O)")
df13.description = (
    "Spring Boot application reads a binary file from the Physical File System "
    "via Java NIO using the PhysicalOsPath stored in FileVersion. "
    "Path is normalised and validated before read. "
    "FileHash from FileVersion is used to verify file integrity after read."
)
df13.protocol = "Java NIO (OS I/O)"
df13.isResponse = True
df13.responseTo = df12
df13.order = 13

# ── DF-14  App → External Log : Forward audit logs (HTTPS) ───────────────────
df14 = Dataflow(app, ext_log, "DF-14: Forward Structured Audit Logs (HTTPS)")
df14.description = (
    "Spring Boot application forwards structured JSON audit log events to the "
    "external ELK/SIEM system in real time over HTTPS/TLS. "
    "Each event includes: timestamp, userId, action, resourceId, resourceType, "
    "sourceIP. Authenticated via API key. "
    "Logs are NOT stored exclusively on the local server — the external system "
    "provides the immutable audit trail required for non-repudiation."
)
df14.protocol = "HTTPS/TLS"
df14.tlsVersion = TLSVersion.TLSv13
df14.order = 14

# ─────────────────────────────────────────────────────────────────────────────
# PROCESS
# ─────────────────────────────────────────────────────────────────────────────
tm.process()