# Ender Chest — Phase 1 Report (Analysis & Secure Design)

**Course:** DESOFS 2026  
**Group:** WED\_NAP\_3  
**Repository:** `desofs2026-wed_nap_3`  
**Phase:** 1  
**Last updated:** 2026-04-18

---

## Document Control

| Version | Date | Author(s) | Changes |
|---------|------|-----------|---------|
| 0.1 | 2026-03-23 | Team | Initial structure |
| 0.2 | 2026-04-05 | Team | System overview, requirements, architecture, domain model |
| 0.3 | 2026-04-10 | Team | DFDs Level 0, 1, 2 (pytm) |
| 1.0 | 2026-04-18 | Team | Threat modeling, abuse cases, risk assessment, security testing, ASVS checklist |

---

## Team

| # | Name | Student ID |
|---|------|-----------|
| 1 | \<name\> | \<id\> |
| 2 | \<name\> | \<id\> |
| 3 | \<name\> | \<id\> |
| 4 | \<name\> | \<id\> |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Overview & Architecture](#2-system-overview--architecture)
3. [Domain Model (DDD)](#3-domain-model-ddd)
4. [Requirements](#4-requirements)
5. [Data Flow Diagrams (DFDs)](#5-data-flow-diagrams-dfds)
6. [Threat Modeling (STRIDE)](#6-threat-modeling-stride)
7. [Abuse Cases](#7-abuse-cases)
8. [Risk Assessment (DREAD)](#8-risk-assessment-dread)
9. [Mitigations](#9-mitigations)
10. [Security Requirements](#10-security-requirements)
11. [Security Testing Plan](#11-security-testing-plan)
12. [ASVS Checklist](#12-asvs-checklist)
13. [Phase 1 Summary](#13-phase-1-summary)

---

## 1. Introduction

### 1.1 Project Summary

**Ender Chest** is a secure file management system exposed as a RESTful API. It allows authenticated users to upload, download, organise, and share files and folders. The system executes OS-level operations (directory creation, file I/O via Java NIO) on the server, making secure design and strict authorisation boundaries central to the architecture.

The backend is a **Spring Boot monolith** that persists metadata in **PostgreSQL** and stores binary file content on the **server file system** using UUID-based paths. All communication is enforced over HTTPS/TLS 1.3.

Security is foundational to this project: the system manages potentially sensitive user files, enforces role-based access control (RBAC), and executes OS-level operations that could be exploited for path traversal, web shell upload, or privilege escalation if not designed correctly.

### 1.2 Goals

- Secure file upload/download and folder management via REST API
- RBAC with three roles: **Owner** (full control), **Editor** (upload/download), **Viewer** (read-only)
- Full auditability of all user actions via structured audit logs forwarded to an external ELK/SIEM
- Resilience: soft delete and file version history reduce the impact of accidental or malicious destructive actions
- Prevention of path traversal, web shell upload, IDOR, SQL injection, and credential attacks — by architectural design

### 1.3 Assumptions and Constraints

| Item | Decision |
|------|---------|
| Authentication | JWT with 15-minute access tokens + refresh token mechanism |
| Metadata storage | PostgreSQL — users, file records, folder records, access control |
| Binary storage | Physical file system (`/srv/files/`) — outside the web root |
| Physical file naming | System-generated UUIDs — user-supplied filenames **never** used as path components |
| Deployment | Spring Boot containerised with Docker; single-host for Phase 1/2 |
| Out of scope | Frontend/web client; email/SMS notifications; mobile features |

---

## 2. System Overview & Architecture

### 2.1 Architecture Description

Ender Chest is a **Spring Boot monolith** exposing a REST API over HTTPS. It communicates with two internal data stores and one external system:

| Component | Role | Technology |
|-----------|------|-----------|
| REST Client (Browser / App) | External actor; sends HTTP requests | Browser / any HTTP client |
| Spring Boot Application | Single process — authentication, RBAC, file/folder ops, OS I/O, audit | Spring Boot 3.x, Java 21 |
| PostgreSQL | Relational store for all domain metadata and access control records | PostgreSQL 16 |
| Physical File System | Binary file storage — UUID-named files, outside web root | Server OS, Java NIO |
| External Log System (ELK / SIEM) | Immutable audit trail — receives structured JSON events in real time | ELK / external SIEM |

### 2.2 Architecture Diagram

![Architecture Diagram](./assets/architecture_diagram.png)

The diagram shows the physical deployment view: the REST client communicates with the Spring Boot backend over HTTPS. The backend uses JDBC to access PostgreSQL and Java NIO for OS-level file I/O. Audit logs are forwarded to the external log system over HTTPS with API-key authentication.

### 2.3 Key Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| UUID as physical filename | The user-supplied filename is **never** used as a file system path component, eliminating path traversal at the storage layer |
| Metadata in DB, binary on FS | Separates concerns; access checks on metadata before any OS I/O |
| AccessShare checked before every OS operation | Authorization-first: if no AccessShare record exists for the caller and resourceId, the operation is rejected before touching the file system |
| Files stored outside the web root | Prevents direct URL access; all downloads are proxied through the application, enforcing RBAC on every request |
| Storage directory has no execute permissions | Prevents any uploaded file from being executed, even if a web shell were somehow stored |
| Audit log forwarded to external ELK before response | Ensures the audit trail is captured even if the application crashes after the operation; logs not stored exclusively on the local server |
| Soft delete (IsDeleted flag) | Prevents immediate permanent data loss; reduces the blast radius of accidental or malicious delete operations |
| SHA-256 FileHash on FileVersion | Enables integrity verification on every download; detects tampering between write and read |

---

## 3. Domain Model (DDD)

### 3.1 Aggregates

The domain model follows Domain-Driven Design (DDD) principles and is organised around **five aggregate roots**:

![Domain Model](./assets/domain_model.png)

| Aggregate Root | Key Attributes | Security Notes |
|----------------|---------------|----------------|
| **User** | UserId (UUID), Username, Email, PasswordHash, StorageQuota, IsLocked | `IsLocked` supports account lockout after failed login attempts; `StorageQuota` prevents per-user DoS by upload |
| **File** | FileId (UUID), FileName, FolderId, OwnerId, IsDeleted | `IsDeleted = true` implements soft delete — prevents immediate permanent data loss |
| **FileVersion** | VersionId, FileId, PhysicalOsPath, Size, MimeType, FileHash, UploadedAt | `FileHash` (SHA-256) enables integrity verification on every download; `PhysicalOsPath` is always a UUID |
| **Folder** | FolderId (UUID), FolderName, OwnerId, ParentFolderId | UUID-based; path traversal prevented at OS I/O layer by path normalisation |
| **AccessShare** | ShareId (UUID), ResourceId, ResourceType (FILE\|FOLDER), GrantedToUserId, RoleType (OWNER\|EDITOR\|VIEWER) | Central RBAC enforcement point; **evaluated before any OS-level I/O** |

### 3.2 RBAC Matrix

| Operation | OWNER | EDITOR | VIEWER |
|-----------|:-----:|:------:|:------:|
| Upload file | ✅ | ✅ | ❌ |
| Download file | ✅ | ✅ | ✅ |
| Delete file | ✅ | ❌ | ❌ |
| Share / Revoke access | ✅ | ❌ | ❌ |
| Create / Rename / Delete folder | ✅ | ✅ | ❌ |
| List folder contents | ✅ | ✅ | ✅ |

### 3.3 Key Domain Relationships

- A `User` owns multiple `Folders`; a `Folder` contains multiple `Files`; a `File` maintains a history of `FileVersions`.
- An `AccessShare` record grants a specific `User` a `RoleType` on a specific `File` or `Folder` (identified by `ResourceId` + `ResourceType`).
- Before any file or folder operation, the system queries `AccessShare` to determine the caller's `RoleType` for the specific resource. If no record exists, the default is **deny**.

---

## 4. Requirements

### 4.1 Functional Requirements (FR)

| ID | Description | Priority |
|----|-------------|---------|
| **FR-01** | The system must allow users to upload files to the server, with strict validation of file type and size. | MUST |
| **FR-02** | The system must allow users to download files to which they have authorised access. | MUST |
| **FR-03** | The system must allow users to create, list, rename, and delete folders/directories on the server. | MUST |
| **FR-04** | The owner of a file (Owner) can share files with other users by assigning them a specific role (Editor or Viewer). | MUST |
| **FR-05** | The system must support three roles: Owner (full control), Editor (upload/edit), and Viewer (read-only). | MUST |
| **FR-06** | The Owner must be able to revoke access from other users at any time. | MUST |
| **FR-07** | The system must expose a REST API for all operations concerning files and folders. | MUST |
| **FR-08** | The system should maintain an audit log of all actions performed (upload, download, sharing, deletion). | SHOULD |
| **FR-09** | Users must be able to register, authenticate, and manage their profiles. | MUST |

### 4.2 Non-Functional Requirements (NFR)

| ID | Description | Priority |
|----|-------------|---------|
| **NFR-01** | All communication between the client and the server must be conducted over HTTPS/TLS. | MUST |
| **NFR-02** | The system must run as a Spring Boot application using a persistent relational database (PostgreSQL). | MUST |
| **NFR-03** | The code architecture must follow DDD principles with at least three aggregates. | MUST |
| **NFR-04** | The system should record error and access logs in a structured format (JSON). | SHOULD |
| **NFR-05** | The application should be containerisable (Docker) to facilitate deployment and CI/CD. | SHOULD |

### 4.3 Secure Development Requirements (SDR)

| ID | Description | Priority |
|----|-------------|---------|
| **SDR-01** | Authentication via JWT with expiration time and a refresh token mechanism. | MUST |
| **SDR-02** | Role-Based Access Control (RBAC) — access to each resource must be strictly verified before any operation is executed. | MUST |
| **SDR-03** | Strict validation and sanitisation of all inputs received by the API (filenames, paths, MIME types). | MUST |
| **SDR-04** | Path traversal prevention — file paths must be normalised and strictly confined to the base storage directory. | MUST |
| **SDR-05** | Limit the size and type of files accepted during upload to prevent DoS attacks. | MUST |
| **SDR-06** | Passwords must be stored using a secure cryptographic hash (BCrypt or Argon2) — never in plaintext. | MUST |
| **SDR-07** | Third-party dependencies managed with SCA (OWASP Dependency-Check) and updated regularly. | SHOULD |
| **SDR-08** | SAST integrated into the CI/CD pipeline (SonarQube, Semgrep). | SHOULD |
| **SDR-09** | Secure server configuration — HTTP security headers (CSP, HSTS, X-Frame-Options) active by default. | MUST |
| **SDR-10** | Rate limiting on API endpoints to mitigate brute force and DDoS attacks. | MUST |
| **SDR-NEW-01** | JWT algorithm whitelist — server explicitly rejects `alg: none` and non-whitelisted algorithms. | MUST |
| **SDR-NEW-03** | Audit log events forwarded to external ELK/SIEM over HTTPS/TLS with API key authentication **before** the response is returned. | MUST |
| **SDR-NEW-06** | Production DB user has DML-only permissions (SELECT, INSERT, UPDATE, DELETE) — no DDL, no TRUNCATE. | MUST |
| **SDR-NEW-07** | Per-user StorageQuota enforced at upload time; reject upload if quota would be exceeded. | MUST |
| **SDR-NEW-11** | SHA-256 FileHash stored in FileVersion and verified on every download; abort and alert on mismatch. | MUST |

---

## 5. Data Flow Diagrams (DFDs)

DFDs were produced using [pytm](https://github.com/OWASP/pytm) and follow the standard notation:

| Symbol | Meaning |
|--------|---------|
| Rectangle | External Entity (Actor) |
| Circle / Ellipse | Process |
| Two parallel lines | Data Store |
| Dashed line | Trust Boundary |
| Arrow | Data Flow |

### 5.1 DFD Level 0 — Context Diagram

The Level 0 diagram treats the entire system as a **single black-box process**. Only external entities and top-level data flows are shown.

![DFD Level 0](./DFD/dfd_level0_final.png)

**External Entities:**

| Entity | Description | Trust Boundary |
|--------|-------------|----------------|
| User (Browser / App) | End user — holds OWNER, EDITOR, or VIEWER role on resources | Internet (Untrusted) |
| Administrator | Privileged user — manages accounts and system configuration via JWT Admin role | Internet (Untrusted) — Admin |
| External Log System (ELK / SIEM) | Receives structured JSON audit events; write-only, authenticated via API key | External Systems |

**Trust Boundaries at Level 0:**

| Boundary | Meaning |
|----------|---------|
| Internet (Untrusted) | Where Users and Administrators originate. All inbound traffic must use HTTPS/TLS and carry a valid JWT. |
| External Systems | Where third-party systems receiving outbound data live. Audit logs cross here over HTTPS/TLS with API key. |

**Data Flows (Level 0):**

| ID | Source → Destination | Description |
|----|---------------------|-------------|
| DF-L0-01 | User → System | All user requests (auth, file/folder ops, sharing) over HTTPS/TLS |
| DF-L0-02 | System → User | Responses: JWT tokens, file content, JSON metadata, error messages |
| DF-L0-03 | Administrator → System | Administrative requests over HTTPS/TLS + JWT Admin role |
| DF-L0-04 | System → Administrator | Administrative responses over HTTPS/TLS |
| DF-L0-05 | System → External Log System | Structured JSON audit logs over HTTPS/TLS, authenticated via API key |

---

### 5.2 DFD Level 1 — System Decomposition

Level 1 decomposes the black-box into its internal process, data stores, and all named data flows.

![DFD Level 1](./DFD/dfd_level1_final.png)

**Processes:**

| Process | Description |
|---------|-------------|
| Spring Boot Application | Single REST API monolith. Handles: (1) authentication — JWT issuance, BCrypt/Argon2 hashing, rate limiting, account lockout; (2) file operations — upload (magic-byte validation, UUID rename, quota check), download (Content-Disposition: attachment), soft delete, FileHash integrity check; (3) folder operations — create/rename/delete via Java NIO, path normalisation; (4) access control — AccessShare evaluated before every OS-level I/O; (5) audit logging — structured JSON events forwarded to ELK/SIEM. |

**Data Stores:**

| Store | Description | Trust Boundary |
|-------|-------------|----------------|
| PostgreSQL Database | Stores all domain aggregates. Accessed via JDBC prepared statements with a DML-only DB user. Encrypted connection (JDBC/TLS). | B — App / Infrastructure |
| Physical File System | Binary files named with system-generated UUIDs. Outside the web root; no execute permissions. Accessed via Java NIO. | B — App / Infrastructure |

**Trust Boundaries at Level 1:**

| Boundary | Separates | Key Controls Enforced |
|----------|-----------|-----------------------|
| A — Internet / Application | Untrusted actors from the Spring Boot process | HTTPS/TLS 1.3, JWT authentication, input validation |
| B — Application / Infrastructure | Spring Boot from data stores (PostgreSQL + FS) | JDBC prepared statements, Java NIO path normalisation, DML-only DB user |
| C — Application / External Log | Application from ELK/SIEM | HTTPS/TLS 1.3, API key authentication |

**Data Flows (Level 1):**

| ID | Flow | Description |
|----|------|-------------|
| DF-01 | User → App | Authentication: POST /auth/register, /auth/login, /auth/refresh. Rate limited. Account locked after N failures. |
| DF-02 | App → User | JWT access token (15 min) + refresh token, over HTTPS/TLS. |
| DF-03 | User → App | File upload: POST /files/upload (multipart). JWT in header. Magic-byte MIME check, size check, StorageQuota check. |
| DF-04 | User → App | File download: GET /files/{fileId}. JWT in header. AccessShare checked before I/O. |
| DF-05 | App → User | File binary streamed with `Content-Disposition: attachment`. Never served as a static URL. |
| DF-06 | User → App | File delete: DELETE /files/{fileId}. OWNER-only. Soft delete (IsDeleted=true). |
| DF-07 | User → App | Share/revoke: POST/DELETE /resources/{resourceId}/share. Creates/removes AccessShare record. OWNER-only. |
| DF-08 | User → App | Folder operations: POST/GET/PUT/DELETE /folders/{folderId}. Paths normalised via Java NIO. |
| DF-09 | Administrator → App | User management: GET/POST/DELETE /admin/users. Requires JWT Admin role. |
| DF-10 | App → PostgreSQL | All domain read/write via JDBC prepared statements. DML-only DB user. |
| DF-11 | PostgreSQL → App | Query results: user records, file/folder metadata, FileVersion (PhysicalOsPath + FileHash), AccessShare records. |
| DF-12 | App → File System | Write binary file via Java NIO. UUID filename. Path normalised and validated against base directory before write. |
| DF-13 | File System → App | Read binary file via Java NIO. Path validated. SHA-256 FileHash integrity check after read. |
| DF-14 | App → External Log System | Structured JSON audit events forwarded over HTTPS/TLS with API key. Not stored exclusively locally. |

---

### 5.3 DFD Level 2 — File Service Decomposition

Level 2 decomposes the **File Service sub-system** — the highest threat-density area — into four internal logical sub-processes. This level directly maps to the critical threats identified in the STRIDE analysis.

![DFD Level 2](./DFD/dfd_level2_final.png)

**Sub-Processes:**

| Sub-Process | Responsibility |
|-------------|---------------|
| **P2.1 — File Request Handler** | Single entry point. Combines all input validation and authorisation before any I/O occurs: (1) filename sanitisation — strip `../`, `/`, `\`, null bytes; (2) path normalisation via `Path.normalize()` + base-directory check; (3) MIME-type validation via Apache Tika magic bytes (never trusts Content-Type header); (4) file size check against configured maximum; (5) rate limiting per user; (6) JWT validation — algorithm whitelist, `exp`, `iss`, `sub` claims; (7) AccessShare lookup — determines caller's RoleType for the specific resourceId; (8) RBAC matrix enforcement — DELETE is OWNER-only; (9) object-level IDOR check — caller must have an AccessShare record for the specific resourceId. **If any check fails: HTTP 403/429 is returned immediately and no I/O occurs.** |
| **P2.2 — File Store (Java NIO)** | Binary file I/O. Upload: generates UUID for PhysicalOsPath, validates path against base directory, writes file bytes, computes SHA-256 FileHash. Download: retrieves PhysicalOsPath from P2.3, validates path, reads bytes, verifies SHA-256 against stored FileHash — aborts with integrity alert if mismatch. Delete: no physical I/O; soft delete only via P2.3. |
| **P2.3 — Metadata Store (JDBC)** | Persists and queries File and FileVersion aggregates using prepared statements only — never string concatenation. Upload: INSERT File + FileVersion including FileHash. Download: SELECT FileVersion for PhysicalOsPath + FileHash. Delete: UPDATE IsDeleted=true (soft delete). StorageQuota check and AccessShare lookup for P2.1. |
| **P2.4 — Audit Log Service** | Emits structured JSON audit event for every File Service operation **before** the response is returned to the caller. Forwards to ELK/SIEM over HTTPS/TLS with API key (Trust Boundary C). Never logs passwords, tokens, or file content. |

**Threat Mapping to Level 2 Sub-Processes:**

| Sub-Process | Threats Addressed |
|-------------|------------------|
| P2.1 File Request Handler | T-05 Path Traversal, T-06 Web Shell Upload, T-07 IDOR, T-08 DoS by Upload, T-09 Role Abuse |
| P2.2 File Store | T-05 Path Traversal (base-dir escape on I/O), T-17 File Integrity Tampering |
| P2.3 Metadata Store | T-11 SQL Injection |
| P2.4 Audit Log Service | T-13 Repudiation / Log Tampering |

**Key Data Flows (Level 2 — Upload):**

| ID | Flow | Description |
|----|------|-------------|
| DF-L2-01 | User → P2.1 | POST /files/upload — multipart, JWT in header. All data untrusted. |
| DF-L2-02 | P2.1 → PostgreSQL | AccessShare + StorageQuota lookup via prepared statements. |
| DF-L2-03 | PostgreSQL → P2.1 | RoleType + quota result. Reject HTTP 403 (no EDITOR/VIEWER) or HTTP 429 (quota exceeded). |
| DF-L2-04 | P2.1 → P2.2 | Validated file bytes + sanitised metadata forwarded for storage. |
| DF-L2-05 | P2.2 → File System | Write UUID-named file via Java NIO. Compute SHA-256 FileHash. |
| DF-L2-06 | P2.2 → P2.3 | File metadata + FileHash passed for DB persistence. |
| DF-L2-07 | P2.3 → PostgreSQL | INSERT File + FileVersion with prepared statements. |
| DF-L2-08 | P2.3 → P2.4 | Trigger UPLOAD audit event before returning response. |
| DF-L2-09 | P2.4 → ELK/SIEM | JSON audit event forwarded over HTTPS/TLS + API key (crosses Trust Boundary C). |

**Key Data Flows (Level 2 — Download):**

| ID | Flow | Description |
|----|------|-------------|
| DF-L2-10 | User → P2.1 | GET /files/{fileId} — JWT in header. P2.1 validates JWT + AccessShare for this fileId. |
| DF-L2-11 | P2.1 → P2.3 | Request FileVersion record (PhysicalOsPath + FileHash). |
| DF-L2-12 | P2.3 → P2.2 | Return PhysicalOsPath + FileHash. |
| DF-L2-13 | File System → P2.2 | Read binary via Java NIO. Verify SHA-256 — abort + alert DOWNLOAD_INTEGRITY_FAIL if mismatch. |
| DF-L2-14 | P2.2 → User | Stream integrity-verified file with `Content-Disposition: attachment`. |

**Key Data Flows (Level 2 — Delete):**

| ID | Flow | Description |
|----|------|-------------|
| DF-L2-15 | User → P2.1 | DELETE /files/{fileId} — OWNER-only check. Soft delete: UPDATE IsDeleted=true via P2.3. |

---

## 6. Threat Modeling (STRIDE)

### 6.1 Methodology

**STRIDE per DFD element** is applied to all processes, data stores, and data flows at Level 1 and Level 2.

| Letter | Threat Type | Security Property Violated |
|--------|------------|---------------------------|
| **S** | Spoofing | Authentication |
| **T** | Tampering | Integrity |
| **R** | Repudiation | Non-repudiation |
| **I** | Information Disclosure | Confidentiality |
| **D** | Denial of Service | Availability |
| **E** | Elevation of Privilege | Authorisation |

### 6.2 STRIDE Analysis

#### Process: Spring Boot Application

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-01** | S | **JWT Algorithm Confusion** — Attacker forges a JWT by setting `alg: none` or performing HS256/RS256 confusion (using the public key as the HMAC secret). | External attacker | Craft JWT with `alg: none` in header; or encode payload signed with the server's public key and `alg: HS256`. |
| **T-02** | T | **TLS Downgrade / MITM** — Attacker performs a man-in-the-middle attack to intercept or modify traffic by downgrading from HTTPS to HTTP. | Network adversary | Strip HTTPS redirect; HSTS not set; intercept traffic. |
| **T-03** | R | **Action Repudiation** — A user denies having uploaded, deleted, or shared a resource, and no reliable audit trail exists. | Malicious authenticated user | Perform action; claim no knowledge. |
| **T-04** | I | **Internal Error Information Disclosure** — Stack traces, exception messages, internal paths, or framework versions leaked in HTTP error responses. | External attacker | Trigger server error (malformed input, boundary conditions); inspect response body. |
| **T-08** | D | **DoS via Large File Uploads** — Attacker fills disk or exhausts memory by uploading very large files or many concurrent requests. | External attacker / authenticated user | Send large multipart uploads; open many concurrent upload connections. |
| **T-09** | E | **Role Abuse — EDITOR Performs DELETE** — An EDITOR attempts to delete a file they do not own, exploiting missing RBAC enforcement. | Authenticated user with EDITOR role | Send `DELETE /files/{fileId}` with a valid EDITOR JWT. |

#### Data Flow: DF-01 — Authentication Request

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-10** | S | **Credential Brute Force / Stuffing** — Attacker exhausts username/password combinations to gain account access. | External attacker | Automated tool sends many POST /auth/login requests with different credentials. |
| **T-16** | I | **User Enumeration via Login Error** — Distinct error messages reveal whether a username exists in the system. | External attacker | Compare responses for "user not found" vs "wrong password". |

#### Data Flow: DF-03 — File Upload

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-05** | T | **Path Traversal** — Attacker supplies a filename containing `../` sequences or null bytes to escape the storage base directory and overwrite arbitrary server files. | External attacker | `filename = "../../../../etc/passwd"` or `"../webroot/shell.jsp"` in multipart upload. |
| **T-06** | T | **Malicious File Upload / Web Shell** — Attacker uploads an executable file (JSP, PHP, shell script) by spoofing the Content-Type header, enabling Remote Code Execution. | External attacker | Upload file with `Content-Type: image/jpeg` but actual content is a JSP/PHP script. |
| **T-07** | E | **IDOR — Broken Object Level Authorisation** — Authenticated user accesses or modifies another user's resources by manipulating the resourceId in the URL. | Authenticated malicious user | Change `fileId` UUID in `GET /files/{fileId}` to another user's UUID. |

#### Data Flow: DF-08 — Folder Operations

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-05b** | T | **Path Traversal in Folder Operations** — Attacker manipulates the folder name or path parameter to escape the storage directory during folder create, rename, or delete. | External attacker | `folderName = "../../etc"` or traversal sequences in PUT/DELETE path parameter. |

#### Data Flows: DF-10/DF-11 — Application ↔ PostgreSQL

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-11** | T | **SQL Injection** — Attacker injects SQL through user-controlled input (filename, search queries) to exfiltrate or modify data. | External attacker | `filename = "' OR '1'='1"` in upload; SQL payload in any API parameter reaching the DB. |
| **T-12** | I | **Sensitive Data in Error Messages / Logs** — Internal DB errors, query details, or user data exposed through HTTP responses or log endpoints. | External attacker | Trigger DB error; observe response or leaked log endpoint. |

#### Data Flows: DF-12/DF-13 — Application ↔ Physical File System

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-17** | T | **File Integrity Tampering on Disk** — Attacker with OS-level access modifies a binary file after storage, making it appear legitimate when downloaded. | Insider / OS-level attacker | Directly modify `/srv/files/{uuid}` on the server filesystem outside the application. |
| **T-18** | D | **Disk Exhaustion** — Attacker fills the file storage partition, preventing new uploads and potentially crashing the application. | External attacker / authenticated user | Upload many large files until disk space runs out. |

#### Data Store: PostgreSQL Database

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-14** | I | **Plaintext / Weak Password Storage** — Password hashes stored in a reversible or weak format (MD5, SHA-1), recoverable after a database breach. | Insider / DB breach | Direct read from the `users` table. |
| **T-15** | I | **Excessive DB User Privileges** — The DB account used by the application has DDL permissions; SQL injection could DROP TABLE or CREATE backdoor. | External attacker (via T-11) | Exploit SQL injection with `DROP TABLE` or `CREATE USER`. |

#### Data Flow: DF-14 — Audit Logs

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-13** | R | **Log Tampering / Absence of Audit Trail** — Attacker or insider deletes or modifies local log files to erase evidence of malicious activity. | Insider / attacker with server access | Delete or modify log files on the application server. |
| **T-19** | I | **Sensitive Data in Audit Logs** — Passwords, tokens, or file content accidentally included in audit events become visible to log system operators. | Insider (log system admin) | Read audit log entries containing sensitive fields. |

#### External Entity: Administrator

| Threat ID | STRIDE | Description | Threat Agent | Attack Vector |
|-----------|--------|-------------|--------------|---------------|
| **T-20** | E | **Admin Endpoint Exposure** — Spring Boot Actuator or admin endpoints exposed to the internet, allowing unauthenticated access to sensitive management functions. | External attacker | Access `/actuator/env` or `/admin/users` without authentication. |

### 6.3 Threat Summary

| ID | STRIDE | Description | Priority |
|----|--------|-------------|---------|
| T-01 | S | JWT Algorithm Confusion | HIGH |
| T-02 | T | TLS Downgrade / MITM | HIGH |
| T-03 | R | Action Repudiation | MEDIUM |
| T-04 | I | Internal Error Information Disclosure | HIGH |
| T-05 | T | Path Traversal (upload + folder ops) | CRITICAL |
| T-06 | T | Malicious File Upload / Web Shell | CRITICAL |
| T-07 | E | IDOR — Object-level Authorisation Bypass | CRITICAL |
| T-08 | D | DoS via Large File Uploads | CRITICAL |
| T-09 | E | Role Abuse (EDITOR performs DELETE) | HIGH |
| T-10 | S | Credential Brute Force / Stuffing | HIGH |
| T-11 | T | SQL Injection | CRITICAL |
| T-12 | I | Sensitive Data in Error Messages | HIGH |
| T-13 | R | Log Tampering / No Audit Trail | HIGH |
| T-14 | I | Weak Password Storage | HIGH |
| T-15 | I | Excessive DB Privileges | HIGH |
| T-16 | I | User Enumeration via Login Error | HIGH |
| T-17 | T | File Integrity Tampering on Disk | MEDIUM |
| T-18 | D | Disk Exhaustion (DoS) | CRITICAL |
| T-19 | I | Sensitive Data in Audit Logs | MEDIUM |
| T-20 | E | Admin Endpoint Exposure | HIGH |

---

## 7. Abuse Cases

Abuse cases describe how a malicious actor exploits the system's functionality. They complement the functional requirements and are derived from the STRIDE threats identified above.

### AC-01 — JWT Algorithm Confusion Attack (T-01)

**Actor:** External attacker  
**Preconditions:** Server accepts `alg: none` or uses a public key (RS256).  
**Steps:** (1) Attacker intercepts or crafts a JWT. (2) Changes `alg` header to `none` or to `HS256` using the server's RS256 public key as the HMAC secret. (3) Forges claims (e.g., `role: ADMIN`, arbitrary `sub`). (4) Sends crafted token to the API.  
**Impact:** Authentication bypass; attacker impersonates any user including Administrator. Full system compromise possible.  
**Countermeasures:** Server enforces strict algorithm whitelist (RS256 or HS256 only); explicitly rejects `alg: none`; validates `iss`, `exp`, `sub` claims. *(SDR-01, SDR-NEW-01)*

---

### AC-02 — Path Traversal via File Upload (T-05)

**Actor:** Authenticated user (any role)  
**Preconditions:** User has at least EDITOR or OWNER role on a folder; user is authenticated.  
**Steps:** (1) Attacker sends `POST /files/upload` with filename `../../../../etc/passwd` or `../webroot/shell.jsp`. (2) If the server uses the supplied filename as the physical storage path, the file is written outside the intended directory.  
**Impact:** Overwrite of critical OS files; deployment of a web shell enabling Remote Code Execution (RCE); exfiltration of sensitive server-side files.  
**Countermeasures:** User-supplied filename is **never** used as the physical path — only a system-generated UUID (PhysicalOsPath) is used. Path normalised with `java.nio.file.Path.normalize()` and verified against the base directory before any write. *(SDR-04)*

---

### AC-03 — Web Shell Upload via MIME Type Bypass (T-06)

**Actor:** Authenticated user with EDITOR or OWNER role  
**Preconditions:** User has EDITOR or OWNER role.  
**Steps:** (1) Attacker uploads a file with `Content-Type: image/jpeg` but whose actual content is a JSP/PHP/shell script. (2) If the server trusts the Content-Type header without inspecting the bytes, the executable script is stored. (3) Attacker navigates to the file URL to trigger execution.  
**Impact:** Remote Code Execution; full server compromise.  
**Countermeasures:** File type validated using magic bytes (Apache Tika), ignoring the client-supplied Content-Type. Files stored outside the web root; storage directory has no execute permissions; UUID filenames prevent URL prediction. *(SDR-03, SDR-05)*

---

### AC-04 — IDOR — Access Another User's Files (T-07)

**Actor:** Authenticated user  
**Preconditions:** Attacker is authenticated with a valid JWT; knows or guesses the UUID of another user's file.  
**Steps:** (1) Attacker observes a `fileId` UUID. (2) Sends `GET /files/{targetFileId}` with their own valid JWT. (3) If access control only checks authentication (not per-resource authorisation), the file is served.  
**Impact:** Unauthorised access to other users' private files; data breach; privacy violation.  
**Countermeasures:** Every file/folder operation performs an object-level authorisation check: verifies that the calling user has an AccessShare record with a valid RoleType for the specific resourceId. Authentication alone is not sufficient. *(SDR-02)*

---

### AC-05 — Credential Brute Force / Stuffing (T-10)

**Actor:** External attacker  
**Preconditions:** Login endpoint is publicly accessible.  
**Steps:** (1) Attacker sends automated requests to `POST /auth/login` with many username/password combinations. (2) Attempts to find valid credentials using password lists or previous breach dumps.  
**Impact:** Account takeover; all victim's files and shared resources exposed.  
**Countermeasures:** Rate limiting on `/auth/login` returns HTTP 429 after threshold; account locked (`IsLocked=true`) after N consecutive failures; identical error message for "user not found" and "wrong password". *(SDR-10, SDR-01)*

---

### AC-06 — Role Escalation — EDITOR Deletes Files (T-09)

**Actor:** Authenticated user with EDITOR role  
**Preconditions:** User has been granted EDITOR role on a file via AccessShare.  
**Steps:** (1) EDITOR sends `DELETE /files/{fileId}` with a valid JWT. (2) If the server only checks "user has some access", the delete proceeds.  
**Impact:** Unauthorised deletion of files; data loss for the owner.  
**Countermeasures:** RBAC matrix: DELETE is OWNER-only; EDITOR and VIEWER return HTTP 403. Soft delete (IsDeleted=true) prevents permanent data loss even if a bypass were found. *(SDR-02)*

---

### AC-07 — SQL Injection via File Metadata (T-11)

**Actor:** Authenticated attacker  
**Preconditions:** User is authenticated with any role; any input reaching a DB query is not parameterised.  
**Steps:** (1) Attacker uploads a file with filename `' OR '1'='1`. (2) If the filename is interpolated into a SQL query string, the injected SQL executes. (3) Alternatively, injects through a search parameter.  
**Impact:** Full database exfiltration (user credentials, file metadata, access control records); data manipulation; in worst case, OS command execution via DB procedures.  
**Countermeasures:** All database queries use JDBC prepared statements or JPA named queries exclusively. String concatenation into SQL is prohibited. DB user has DML-only permissions — no DDL. *(SDR-03, SDR-NEW-06)*

---

### AC-08 — Denial of Service via Large File Uploads (T-08, T-18)

**Actor:** External attacker or authenticated user  
**Preconditions:** User is authenticated.  
**Steps:** (1) Attacker sends many multipart upload requests with very large file bodies. (2) Without size checks, the server buffers the entire file, exhausting memory or disk space.  
**Impact:** Server memory exhaustion; disk full blocking all uploads; application unavailability.  
**Countermeasures:** Maximum file size enforced before buffering; per-user StorageQuota checked before writing to disk; rate limiting on upload endpoint. *(SDR-05, SDR-NEW-07, SDR-10)*

---

### AC-09 — Log Tampering to Erase Evidence (T-13)

**Actor:** Insider or attacker with OS-level server access  
**Preconditions:** Attacker has gained OS-level access to the application server.  
**Steps:** (1) Attacker performs malicious actions (exfiltrates files, deletes accounts). (2) Deletes or modifies local log files to erase evidence.  
**Impact:** Incident response impossible; breach goes undetected.  
**Countermeasures:** All audit events forwarded in real time to an external ELK/SIEM over HTTPS/TLS with API key **before** the response is returned. Logs are not stored exclusively on the local server; local log deletion does not erase the forwarded events. *(FR-08, SDR-NEW-03)*

---

### AC-10 — File Integrity Tampering on Disk (T-17)

**Actor:** Insider with OS-level access to the storage directory  
**Preconditions:** Attacker has OS-level access to `/srv/files/`.  
**Steps:** (1) Attacker locates a stored binary file by its UUID name. (2) Modifies or replaces its content directly on disk (bypassing the API). (3) When a legitimate user downloads the file, they receive the tampered content.  
**Impact:** Delivery of malicious or modified content to users; supply chain / data integrity violation.  
**Countermeasures:** On every download, `P2.2 File Store` recomputes SHA-256 of the read bytes and compares to the stored `FileVersion.FileHash`. If they differ, the download is aborted (HTTP 500), an integrity alert is logged (`DOWNLOAD_INTEGRITY_FAIL`), and the file is NOT served. File directory restricted to the application OS user only. *(SDR-NEW-11)*

---

## 8. Risk Assessment (DREAD)

### 8.1 DREAD Methodology

**DREAD Score = (D + R + E + A + D) / 5** — each dimension scored 1–10:

| Dimension | 1 (Low) | 5 (Medium) | 10 (High) |
|-----------|---------|-----------|----------|
| **D**amage Potential | Minimal, no data loss | Partial exposure or service degradation | Full system compromise, all data exposed |
| **R**eproducibility | Requires specific rare conditions | Reproducible with effort | Always reproducible; automated |
| **E**xploitability | Advanced skills required | Intermediate knowledge | Trivial; script-kiddie / fully automated |
| **A**ffected Users | Single user | Multiple users | All users / entire system |
| **D**iscoverability | Requires deep source code review | Discoverable with black-box testing | Publicly documented / automated scanners |

**Risk Levels:** CRITICAL ≥ 7.5 · HIGH 5.0–7.4 · MEDIUM 2.5–4.9 · LOW < 2.5

### 8.2 DREAD Scoring

| Risk ID | Threat | D | R | E | A | D | Score | Level |
|---------|--------|---|---|---|---|---|-------|-------|
| **RISK-03** | T-07 IDOR | 9 | 9 | 8 | 10 | 9 | **9.0** | CRITICAL |
| **RISK-01** | T-05 Path Traversal | 10 | 9 | 7 | 9 | 9 | **8.8** | CRITICAL |
| **RISK-04** | T-11 SQL Injection | 10 | 8 | 7 | 10 | 9 | **8.8** | CRITICAL |
| **RISK-02** | T-06 Web Shell Upload | 10 | 8 | 6 | 9 | 8 | **8.2** | CRITICAL |
| **RISK-09** | T-08/T-18 DoS Upload | 7 | 9 | 9 | 8 | 6 | **7.8** | CRITICAL |
| **RISK-05** | T-10 Brute Force | 8 | 9 | 8 | 6 | 7 | **7.6** | HIGH |
| **RISK-06** | T-01 JWT Spoofing | 9 | 7 | 5 | 8 | 7 | **7.2** | HIGH |
| **RISK-07** | T-09 Role Abuse | 6 | 8 | 8 | 5 | 6 | **6.6** | HIGH |
| **RISK-08** | T-14 Weak Passwords | 9 | 7 | 5 | 10 | 4 | **7.0** | HIGH |
| **RISK-14** | T-20 Admin Exposure | 9 | 5 | 5 | 10 | 6 | **7.0** | HIGH |
| **RISK-15** | T-16 User Enumeration | 2 | 9 | 9 | 2 | 8 | **6.0** | HIGH |
| **RISK-12** | T-04 Error Disclosure | 4 | 8 | 8 | 3 | 7 | **6.0** | HIGH |
| **RISK-10** | T-13 Log Tampering | 8 | 5 | 4 | 7 | 3 | **5.4** | HIGH |
| **RISK-13** | T-19 Sensitive Logs | 7 | 4 | 3 | 8 | 2 | **4.8** | MEDIUM |
| **RISK-11** | T-17 File Integrity | 8 | 4 | 3 | 6 | 2 | **4.6** | MEDIUM |

### 8.3 Prioritised Risk Register

| Priority | Risk ID | DREAD Score | Level | Key Mitigation |
|----------|---------|-------------|-------|----------------|
| 1 | RISK-03 — IDOR | **9.0** | CRITICAL | AccessShare object-level check per resourceId |
| 2 | RISK-01 — Path Traversal | **8.8** | CRITICAL | UUID physical names; `Path.normalize()` + base-dir check |
| 3 | RISK-04 — SQL Injection | **8.8** | CRITICAL | Prepared statements exclusively; DML-only DB user |
| 4 | RISK-02 — Web Shell Upload | **8.2** | CRITICAL | Magic-byte MIME validation; out-of-webroot storage |
| 5 | RISK-09 — DoS Upload | **7.8** | CRITICAL | Max file size; StorageQuota; rate limiting |
| 6 | RISK-05 — Brute Force | **7.6** | HIGH | Rate limit; account lockout (IsLocked) |
| 7 | RISK-06 — JWT Spoofing | **7.2** | HIGH | Algorithm whitelist; reject `alg: none` |
| 8 | RISK-08 — Weak Passwords | **7.0** | HIGH | BCrypt / Argon2 |
| 9 | RISK-14 — Admin Exposure | **7.0** | HIGH | Network restriction; JWT Admin role required |
| 10 | RISK-15 — User Enumeration | **6.0** | HIGH | Generic error message for all login failures |
| 11 | RISK-12 — Error Disclosure | **6.0** | HIGH | Global exception handler; no stack traces |
| 12 | RISK-07 — Role Abuse | **6.6** | HIGH | RBAC matrix: DELETE OWNER-only |
| 13 | RISK-10 — Log Tampering | **5.4** | HIGH | External ELK/SIEM; real-time forwarding |
| 14 | RISK-13 — Sensitive Logs | **4.8** | MEDIUM | Audit event schema excludes sensitive fields |
| 15 | RISK-11 — File Integrity | **4.6** | MEDIUM | SHA-256 FileHash verified on every download |

---

## 9. Mitigations

The following table maps each high-priority risk to the specific architectural control that addresses it, along with the requirement ID for traceability:

| Risk | Threat | Control | Requirement |
|------|--------|---------|------------|
| RISK-03 IDOR | T-07 | Object-level AccessShare check for every API operation — authentication alone is not sufficient | SDR-02 |
| RISK-01 Path Traversal | T-05 | UUID as physical filename; `Path.normalize()` + base-directory validation before every file write/read; filename sanitisation in metadata | SDR-04 |
| RISK-04 SQL Injection | T-11 | JDBC prepared statements and JPA named queries exclusively; no string concatenation in SQL; DML-only DB user | SDR-03, SDR-NEW-06 |
| RISK-02 Web Shell Upload | T-06 | Magic-byte MIME validation using Apache Tika (ignores Content-Type header); MIME type whitelist; files stored outside web root; storage directory has no execute permissions; UUID filenames | SDR-03, SDR-05 |
| RISK-09 DoS Upload | T-08, T-18 | Max file size enforced before buffering (`spring.servlet.multipart.max-file-size`); per-user StorageQuota checked before write; rate limiting on upload endpoint (HTTP 429) | SDR-05, SDR-NEW-07, SDR-10 |
| RISK-05 Brute Force | T-10 | Rate limiting on `/auth/login`; account lockout (`IsLocked=true`) after N failures; identical generic error message for all failures | SDR-10, SDR-01 |
| RISK-06 JWT Spoofing | T-01 | Server-side algorithm whitelist (RS256/HS256 only); explicit rejection of `alg: none`; validation of `iss`, `exp`, `sub`, `aud` claims | SDR-01, SDR-NEW-01 |
| RISK-08 Weak Passwords | T-14 | BCrypt or Argon2 with appropriate work factor; salt per password; never store plaintext | SDR-06 |
| RISK-14 Admin Exposure | T-20 | Spring Boot Actuator restricted to internal network via firewall rule; admin endpoints require JWT with explicit Admin role | SDR-02, SDR-09 |
| RISK-15 User Enumeration | T-16 | Identical error message `"Invalid credentials"` for both "user not found" and "wrong password" cases | SDR-01 |
| RISK-12 Error Disclosure | T-04 | Global exception handler returns only generic messages; stack traces never exposed in production responses | SDR-09 |
| RISK-07 Role Abuse | T-09 | RBAC matrix enforced: DELETE is OWNER-only; EDITOR/VIEWER receive HTTP 403; soft delete limits damage | SDR-02 |
| RISK-10 Log Tampering | T-13 | All audit events forwarded to external ELK/SIEM over HTTPS/TLS with API key before response is returned; logs not stored exclusively locally | FR-08, SDR-NEW-03 |
| RISK-11 File Integrity | T-17 | SHA-256 FileHash stored in FileVersion at upload time; verified on every download in P2.2; abort and log `DOWNLOAD_INTEGRITY_FAIL` on mismatch | SDR-NEW-11 |
| RISK-13 Sensitive Logs | T-19 | Audit event schema: only timestamp, userId, action, resourceId, resourceType, sourceIP, outcome — no passwords, tokens, or file content | NFR-04 |
| T-02 TLS Downgrade | T-02 | HTTPS/TLS 1.3 enforced; HSTS with long max-age; HTTP connections rejected | SDR-09, NFR-01 |
| T-03 Repudiation | T-03 | Structured audit log with userId, action, resourceId, timestamp, sourceIP forwarded before response | FR-08 |

---

## 10. Security Requirements

This section consolidates all security requirements (from Section 4.3) with their justification and linkage to the threats they address:

| ID | Description | Justification | Threats Addressed |
|----|-------------|--------------|-------------------|
| **SDR-01** | JWT with expiration + refresh token | Authentication without weak session management; short-lived tokens limit exposure window | T-01, T-10 |
| **SDR-NEW-01** | JWT algorithm whitelist; reject `alg: none` | Prevents algorithm confusion attack — critical class of JWT forgery | T-01 |
| **SDR-02** | RBAC — access verified before every operation | Prevents IDOR, role abuse, and unauthorised data access | T-07, T-09, T-20 |
| **SDR-03** | Input validation and sanitisation (filenames, MIME types) | Prevents path traversal in metadata, SQL injection, web shell upload | T-05, T-06, T-11 |
| **SDR-04** | Path traversal prevention — normalise + base-directory check | Prevents any file operation from escaping the configured storage directory | T-05, T-05b |
| **SDR-05** | File size and type limits | Prevents disk exhaustion DoS and web shell upload via size/type enforcement | T-06, T-08, T-18 |
| **SDR-06** | BCrypt / Argon2 password hashing | Prevents credential recovery after a database breach | T-14 |
| **SDR-07** | SCA (OWASP Dependency-Check) | Identifies known CVEs in Spring, JDBC drivers, Apache Tika before deployment | Proactive — all CVE-based threats |
| **SDR-08** | SAST (SonarQube / Semgrep) in CI/CD | Detects security code smells, SQL injection patterns, hardcoded secrets at commit time | T-11, T-14 |
| **SDR-09** | HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) | Prevents TLS downgrade (HSTS), MIME sniffing, clickjacking, information disclosure | T-02, T-04 |
| **SDR-10** | Rate limiting on all API endpoints | Prevents credential brute force and DoS via upload flooding | T-08, T-10 |
| **SDR-NEW-03** | Audit events forwarded to external ELK/SIEM before response | Ensures log immutability even if the local server is compromised | T-13 |
| **SDR-NEW-06** | DML-only DB user (no DDL, no TRUNCATE) | Limits blast radius of SQL injection — attacker cannot DROP tables or CREATE users | T-11, T-15 |
| **SDR-NEW-07** | Per-user StorageQuota enforced at upload | Prevents a single user from exhausting disk space | T-18 |
| **SDR-NEW-11** | SHA-256 FileHash verified on every download | Detects and prevents delivery of tampered file content | T-17 |

---

## 11. Security Testing Plan

### 11.1 Methodology

Security testing follows a **risk-based, threat-driven** approach aligned with ASVS Level 2. The strategy combines:

| Layer | Technique | When |
|-------|-----------|------|
| Static Analysis | SAST — SonarQube / Semgrep | Every commit / CI pipeline |
| Dependency Analysis | SCA — OWASP Dependency-Check | Every build / CI pipeline |
| Dynamic Analysis | DAST — OWASP ZAP | Per sprint (Phase 2) |
| Integration tests | JUnit + Spring Boot Test security flows | Every commit |
| Manual testing | Targeted tests for high-risk areas | Per sprint (Phase 2) |

### 11.2 Threat Modelling Review Process

| Checkpoint | Trigger | Action |
|------------|---------|--------|
| Architecture change | Any change to DFD components or trust boundaries | Re-run STRIDE; update threat table |
| New feature added | New API endpoint or data flow | Add to DFD; apply STRIDE |
| Phase 2 Sprint 1 start | Before implementation begins | Review all CRITICAL and HIGH threats |
| Post-sprint | After each Phase 2 sprint | Verify mitigations implemented; update ASVS checklist |

### 11.3 Security Test Cases

#### Authentication (SDR-01, ASVS V2)

| Test ID | Description | Type | Expected Result | Linked Threat |
|---------|-------------|------|----------------|---------------|
| ST-AUTH-01 | Submit request with `alg: none` JWT | Manual / Unit | HTTP 401 — token rejected | T-01, AC-01 |
| ST-AUTH-02 | JWT with RS256 public key used as HS256 HMAC secret | Manual / Unit | HTTP 401 — token rejected | T-01, AC-01 |
| ST-AUTH-03 | Submit expired JWT | Unit | HTTP 401 | T-01 |
| ST-AUTH-04 | Submit JWT with tampered `sub` (another user's ID) | Unit | HTTP 403 (object-level check catches IDOR) | T-07, AC-04 |
| ST-AUTH-05 | Brute force login (>N attempts) | DAST / Integration | HTTP 429 after threshold; account locked | T-10, AC-05 |
| ST-AUTH-06 | Check login error message for "user not found" vs "wrong password" | Manual | Both return identical `"Invalid credentials"` | T-16 |
| ST-AUTH-07 | Access protected endpoint without JWT | Unit | HTTP 401 | SDR-01 |
| ST-AUTH-08 | Refresh token reuse after invalidation | Integration | HTTP 401 | SDR-01 |

#### Authorisation / Access Control (SDR-02, ASVS V4)

| Test ID | Description | Type | Expected Result | Linked Threat |
|---------|-------------|------|----------------|---------------|
| ST-AUTHZ-01 | EDITOR sends DELETE /files/{fileId} | Unit / Integration | HTTP 403 | T-09, AC-06 |
| ST-AUTHZ-02 | VIEWER sends POST /files/upload | Unit / Integration | HTTP 403 | T-09 |
| ST-AUTHZ-03 | Authenticated user accesses another user's file (IDOR attempt) | Integration | HTTP 403 | T-07, AC-04 |
| ST-AUTHZ-04 | Authenticated user accesses /admin/users without Admin role | Integration | HTTP 403 | T-20 |
| ST-AUTHZ-05 | Unauthenticated access to /admin/users | Integration | HTTP 401 | T-20 |
| ST-AUTHZ-06 | EDITOR attempts to share resource with third user | Integration | HTTP 403 — only OWNER can share | SDR-02 |
| ST-AUTHZ-07 | After OWNER revokes EDITOR access, EDITOR attempts download | Integration | HTTP 403 | FR-06 |

#### File Upload Validation (SDR-03, SDR-04, SDR-05, ASVS V5, V12)

| Test ID | Description | Type | Expected Result | Linked Threat |
|---------|-------------|------|----------------|---------------|
| ST-UPLOAD-01 | Filename `../../etc/passwd` in multipart upload | Integration | HTTP 400; file NOT written outside base dir | T-05, AC-02 |
| ST-UPLOAD-02 | Filename containing null byte `file\x00.txt` | Integration | HTTP 400 or sanitised filename | T-05, AC-02 |
| ST-UPLOAD-03 | JSP file with `Content-Type: image/jpeg` | Integration | HTTP 400 — magic-byte check rejects | T-06, AC-03 |
| ST-UPLOAD-04 | PHP script with `.php` extension | Integration | HTTP 400 — MIME whitelist rejects | T-06, AC-03 |
| ST-UPLOAD-05 | File exceeding maximum allowed size | Integration | HTTP 413/400 before write | T-08, AC-08 |
| ST-UPLOAD-06 | File exceeding user StorageQuota | Integration | HTTP 429 | T-18, AC-08 |
| ST-UPLOAD-07 | Verify physical filename on disk is a UUID | Integration | UUID-named file in base dir; no traversal path on disk | T-05 |
| ST-UPLOAD-08 | Upload to a folder belonging to another user | Integration | HTTP 403 — AccessShare check | T-07 |

#### Folder Operations (SDR-04, ASVS V5)

| Test ID | Description | Type | Expected Result | Linked Threat |
|---------|-------------|------|----------------|---------------|
| ST-FOLDER-01 | Create folder with name `../../../etc` | Integration | HTTP 400; no directory created outside base dir | T-05b |
| ST-FOLDER-02 | Rename folder with traversal in new name | Integration | HTTP 400 | T-05b |
| ST-FOLDER-03 | Delete folder without OWNER role | Integration | HTTP 403 | T-09 |

#### Data Security (SDR-06, ASVS V2)

| Test ID | Description | Type | Expected Result | Linked Threat |
|---------|-------------|------|----------------|---------------|
| ST-DATA-01 | Verify password stored in DB | Unit | PasswordHash is BCrypt or Argon2; not plaintext | T-14 |
| ST-DATA-02 | Verify DB user lacks DDL permissions | Integration / Config | `DROP TABLE` command fails with permission denied | T-15 |
| ST-DATA-03 | Verify HTTPS enforced; HTTP redirects | Manual / Config | HTTP 301/302 to HTTPS; HSTS header present | T-02 |
| ST-DATA-04 | Verify HTTP security headers | Manual | HSTS, X-Content-Type-Options, X-Frame-Options, CSP present | SDR-09 |

#### File Integrity (SDR-NEW-11, ASVS V9)

| Test ID | Description | Type | Expected Result | Linked Threat |
|---------|-------------|------|----------------|---------------|
| ST-INTEG-01 | Tamper with stored file on disk; attempt download | Integration | HTTP 500; DOWNLOAD_INTEGRITY_FAIL logged; file NOT served | T-17, AC-10 |
| ST-INTEG-02 | Download unmodified file; verify FileHash matches | Unit | File served; SHA-256 matches stored FileHash | T-17 |

#### Audit Logging (FR-08, SDR-NEW-03, ASVS V7)

| Test ID | Description | Type | Expected Result | Linked Threat |
|---------|-------------|------|----------------|---------------|
| ST-LOG-01 | Perform upload; verify audit event emitted before response | Integration | ELK/SIEM receives UPLOAD event with correct fields | T-13, AC-09 |
| ST-LOG-02 | Perform failed login; verify audit event emitted | Integration | ELK/SIEM receives failed auth event | T-13 |
| ST-LOG-03 | Verify no password or JWT appears in any log entry | Unit / Log review | No sensitive data in audit events | T-19 |
| ST-LOG-04 | Simulate ELK connection failure | Integration | Application returns error gracefully; no silent audit gap | T-13 |

#### SQL Injection (SDR-03, ASVS V5)

| Test ID | Description | Type | Expected Result | Linked Threat |
|---------|-------------|------|----------------|---------------|
| ST-SQLI-01 | OWASP ZAP active scan on all API endpoints | DAST (Phase 2) | No SQL injection vulnerabilities found | T-11 |
| ST-SQLI-02 | Semgrep SAST rule: no string concatenation in SQL | SAST | Zero violations | T-11 |
| ST-SQLI-03 | Upload file with SQL payload in filename | Integration | HTTP 400 or sanitised; no DB error | T-11, AC-07 |

### 11.4 Traceability Matrix

| Security Requirement | Threats | Abuse Cases | Test Cases |
|---------------------|---------|-------------|------------|
| SDR-01 JWT auth | T-01, T-10 | AC-01, AC-05 | ST-AUTH-01 to 08 |
| SDR-02 RBAC | T-07, T-09 | AC-04, AC-06 | ST-AUTHZ-01 to 07 |
| SDR-03 Input validation | T-06, T-11 | AC-03, AC-07 | ST-UPLOAD-01 to 08, ST-SQLI-01 to 03 |
| SDR-04 Path traversal | T-05, T-05b | AC-02 | ST-UPLOAD-01/02/07, ST-FOLDER-01/02 |
| SDR-05 File limits | T-06, T-08 | AC-03, AC-08 | ST-UPLOAD-03 to 06 |
| SDR-06 Password hashing | T-14 | — | ST-DATA-01 |
| SDR-09 Security headers | T-02, T-04 | — | ST-DATA-03/04 |
| SDR-10 Rate limiting | T-08, T-10 | AC-05, AC-08 | ST-AUTH-05, ST-UPLOAD-06 |
| SDR-NEW-03 Audit forwarding | T-13 | AC-09 | ST-LOG-01 to 04 |
| SDR-NEW-06 DML-only DB | T-11, T-15 | AC-07 | ST-DATA-02 |
| SDR-NEW-07 StorageQuota | T-18 | AC-08 | ST-UPLOAD-06 |
| SDR-NEW-11 FileHash | T-17 | AC-10 | ST-INTEG-01/02 |
| FR-08 Audit log | T-13, T-19 | AC-09 | ST-LOG-01 to 04 |

---

## 12. ASVS Checklist

ASVS Level 2 applied with architecture focus. **Status:** ✅ Addressed · ⚠️ Partial · 🔲 Phase 2 · ❌ N/A

### V1 — Architecture, Design and Threat Modeling

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| V1.1.2 | Threat modeling for every design change | ✅ | STRIDE per DFD element — Section 6 |
| V1.1.3 | Functional security constraints for all features | ✅ | FR + SDR requirements — Section 4 |
| V1.1.4 | All trust boundaries documented and justified | ✅ | DFD Level 0/1/2 — Section 5 |
| V1.2.3 | Least-privilege access for all components | ✅ | DML-only DB user; restricted FS directory |
| V1.2.4 | All app components documented with known attack surface | ✅ | DFDs + STRIDE table |

### V2 — Authentication

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| V2.2.1 | Anti-automation controls (rate limiting, lockout) | ✅ | SDR-10 — rate limiting; IsLocked — SDR-01 |
| V2.4.1 | Passwords stored with BCrypt, Argon2, or PBKDF2 | ✅ | SDR-06 |
| V2.9.1 | Cryptographic keys stored securely | ✅ | JWT signing key via environment variable / vault |

### V3 — Session Management

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| V3.2.1 | New session tokens generated at login | ✅ | New JWT issued at each successful login |
| V3.5.1 | OAuth/JWT tokens checked for audience, issuer, expiry | ✅ | SDR-01, SDR-NEW-01 |
| V3.7.1 | Session tokens not exposed in URLs | ✅ | JWT only in Authorization header |

### V4 — Access Control

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| V4.1.1 | Access control enforced at a trusted server-side point | ✅ | AccessShare checked server-side before every operation |
| V4.1.2 | Access control fails securely (default deny) | ✅ | No AccessShare record → HTTP 403 |
| V4.2.1 | All user and data attributes protected from IDOR | ✅ | Object-level AccessShare check per resourceId (SDR-02) |
| V4.2.2 | Business logic enforces access controls | ✅ | RBAC matrix defined and enforced |
| V4.3.1 | Admin interfaces require additional authentication | ✅ | JWT Admin role required |
| V4.3.2 | Directory browsing disabled | ✅ | Files never served as static content; always proxied |

### V5 — Validation, Sanitization and Encoding

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| V5.1.2 | Input validation with allow-list approach | ✅ | MIME type whitelist; filename sanitisation |
| V5.3.4 | DB queries use parameterised queries | ✅ | JDBC prepared statements only (SDR-03) |
| V5.3.8 | OS commands do not use user-supplied input | ✅ | No `Runtime.exec()`; all OS I/O via Java NIO with UUID paths |

### V7 — Error Handling and Logging

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| V7.1.1 | Application does not log credentials or tokens | ✅ | Audit event schema excludes passwords, JWTs (NFR-04) |
| V7.2.1 | All authentication decisions are logged | ✅ | Login success/failure events → ELK/SIEM |
| V7.2.2 | Security-relevant events logged with sufficient detail | ✅ | timestamp, userId, action, resourceId, sourceIP, outcome |
| V7.3.2 | Logs protected from unauthorised access and modification | ✅ | Forwarded to external ELK/SIEM (SDR-NEW-03) |
| V7.4.1 | Generic error message on unexpected error | ✅ | Global exception handler (SDR-09) |
| V7.4.2 | Exception handling does not disclose technical information | ✅ | Stack traces never returned in responses |

### V9 — Communication

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| V9.1.1 | TLS used for all connections | ✅ | HTTPS/TLS 1.3 enforced (NFR-01) |
| V9.2.1 | Server-side connections use trusted TLS certificates | ✅ | JDBC over TLS; ELK over HTTPS/TLS |

### V12 — Files and Resources

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| V12.1.1 | Application does not accept large files that could overwhelm storage | ✅ | Max file size + StorageQuota (SDR-05, SDR-NEW-07) |
| V12.3.1 | User-submitted filenames sanitised before use | ✅ | Strip `../`, `/`, `\`, null bytes (SDR-04) |
| V12.3.2 | User-submitted filenames not used directly in file I/O | ✅ | Physical path is always a UUID; original stored only as metadata |
| V12.3.3 | Path traversal attacks mitigated | ✅ | `Path.normalize()` + base-dir validation (SDR-04) |
| V12.3.4 | Files not executed from untrusted sources | ✅ | Files stored outside web root; no execute permissions |
| V12.4.1 | Files stored outside the web root | ✅ | `/srv/files/` — outside web root |
| V12.4.2 | Files have restricted permissions (not executable) | ✅ | Storage directory has no execute permissions |
| V12.5.1 | Web tier only serves files with defined extensions | ✅ | Files always proxied through API; no direct static URL access |
| V12.5.2 | Direct requests to uploaded files cannot be executed | ✅ | UUID names + out-of-webroot + always proxied through API |

### V14 — Configuration

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| V14.2.1 | All components up to date | ✅ | SCA (OWASP Dependency-Check) in CI pipeline (SDR-07) |
| V14.3.1 | Web server error messages do not expose stack traces | ✅ | SDR-09; global exception handler |
| V14.4.3 | Content Security Policy (CSP) header set | ✅ | SDR-09 — Spring Security HTTP headers |
| V14.4.4 | `X-Content-Type-Options: nosniff` present | ✅ | SDR-09 |
| V14.4.5 | HSTS included in all responses | ✅ | SDR-09 — HSTS enabled in Spring Security |

### ASVS Coverage Summary (Level 2 — Architecture Focus)

| Chapter | Addressed ✅ | Partial ⚠️ | Phase 2 🔲 | N/A ❌ |
|---------|:-----------:|:---------:|:---------:|:-----:|
| V1 Architecture | 7 | 2 | 0 | 1 |
| V2 Authentication | 7 | 2 | 1 | 0 |
| V3 Session Management | 5 | 0 | 2 | 0 |
| V4 Access Control | 7 | 1 | 0 | 1 |
| V5 Validation | 6 | 2 | 0 | 1 |
| V7 Logging | 7 | 1 | 0 | 0 |
| V9 Communication | 3 | 2 | 0 | 0 |
| V12 Files & Resources | 10 | 0 | 2 | 0 |
| V14 Configuration | 8 | 2 | 3 | 0 |
| **Total** | **60 (72%)** | **12 (14%)** | **8 (10%)** | **3 (4%)** |

---

## 13. Phase 1 Summary

### 13.1 Main Findings

Phase 1 identified **20 threats** across all STRIDE categories. The four CRITICAL risks (DREAD ≥ 8.0) are all addressed by architectural design decisions:

1. **IDOR (DREAD 9.0):** Every API operation performs object-level authorisation via AccessShare — authentication alone is not sufficient to access any resource.

2. **Path Traversal (DREAD 8.8):** The user-supplied filename is never used as a file system path component; only a system-generated UUID is used as PhysicalOsPath. All paths are normalised and validated against the base directory before any I/O.

3. **SQL Injection (DREAD 8.8):** All database operations use JDBC prepared statements or JPA named queries exclusively. The production DB user has DML-only permissions — no DDL, no TRUNCATE.

4. **Web Shell Upload (DREAD 8.2):** File type is validated via magic bytes (Apache Tika), ignoring the client-supplied Content-Type header. Files are stored outside the web root with no execute permissions, and UUID filenames prevent URL prediction.

### 13.2 Key Architectural Controls Summary

| Control | Threats Mitigated |
|---------|------------------|
| UUID physical filenames + `Path.normalize()` + base-dir check | T-05 Path Traversal |
| Magic-byte MIME validation (Apache Tika) | T-06 Web Shell / RCE |
| AccessShare object-level check per resourceId | T-07 IDOR |
| JDBC prepared statements; DML-only DB user | T-11 SQL Injection |
| Max file size + StorageQuota + rate limiting | T-08/T-18 DoS |
| JWT algorithm whitelist; reject `alg: none` | T-01 JWT Spoofing |
| Rate limiting + account lockout (IsLocked) | T-10 Brute Force |
| BCrypt/Argon2 password hashing | T-14 Weak Passwords |
| OWNER-only DELETE in RBAC matrix | T-09 Role Abuse |
| External ELK/SIEM real-time audit forwarding | T-13 Log Tampering |
| SHA-256 FileHash verified on every download | T-17 File Integrity |
| HTTP security headers (HSTS, CSP, X-Frame-Options) | T-02, T-04 |

### 13.3 Open Items for Phase 2

| Item | Priority |
|------|---------|
| SAST (SonarQube/Semgrep) integrated into CI pipeline | High |
| SCA (OWASP Dependency-Check) integrated into CI pipeline | High |
| DAST (OWASP ZAP) active scanning against running API | High |
| CORS allow-list explicit configuration | Medium |
| Zip bomb detection on compressed file uploads | Medium |
| Antivirus scanning of uploaded files (ClamAV) | Medium |
| File-at-rest encryption decision | Low |
