#!/usr/bin/env python3
"""
DESOFS 2025/2026 — Secure File Management System
Phase 1 — Threat Modeling: Data Flow Diagram — Level 0 (Context Diagram)

Elemento 2

Level 0 — Context Diagram:
  The entire system is represented as a single Process (black box).
  Only external entities and their high-level interactions with the system
  are shown. No internal decomposition at this level.
  Trust boundaries show where trust levels change between external actors
  and the system.

  Per T3 slides:
    "Level 0 DFDs also called Context diagrams — diagrams that present an
     overview of the system and its interaction with the rest of the world."

  At Level 1 (dfd_level1.py) the system is decomposed into its internal
  data stores and detailed data flows.

DFD Notation (T3 slides):
  Actor      → External Entity  (rectangle)
  Server     → Process          (circle / ellipse)
  Boundary   → Trust Boundary   (dashed line)
  Dataflow   → Data Flow        (arrow)

  Note: No Data Stores appear at Level 0 — they are internal to the system
  and only become visible when the system process is decomposed at Level 1.

Trust Boundaries at Level 0:
  boundary_internet  — Internet side: where untrusted external actors live.
                       User and Administrator originate here. All traffic
                       crossing into the system must use HTTPS/TLS and JWT.
  boundary_external  — External systems side: where third-party systems
                       that the application pushes data to live (ELK/SIEM).
                       Outbound audit logs cross this boundary over HTTPS/TLS.

Run:
  python3 dfd_level0.py --dfd | dot -Tpng -o dfd_level0.png
  python3 dfd_level0.py --dfd | dot -Tsvg -o dfd_level0.svg
"""

from pytm import (
    TM,
    Actor,
    Server,
    Dataflow,
    Boundary,
    TLSVersion,
)

# ─────────────────────────────────────────────────────────────────────────────
# THREAT MODEL
# ─────────────────────────────────────────────────────────────────────────────
tm = TM("Secure File Management System — Level 0 Context Diagram")
tm.description = (
    "Context diagram (Level 0) for the Secure File Management System. "
    "The system is a Spring Boot REST API monolith that allows authenticated "
    "users to upload, download, organise and share files, with RBAC enforced "
    "via the AccessShare aggregate (OWNER / EDITOR / VIEWER). "
    "All communication is over HTTPS/TLS. Audit logs are forwarded to an "
    "external log aggregation system."
)
tm.isOrdered = True
tm.mergeResponses = True

# ─────────────────────────────────────────────────────────────────────────────
# TRUST BOUNDARIES
# ─────────────────────────────────────────────────────────────────────────────

# Boundary: Internet — where untrusted users and admins originate.
# All data flowing from here into the system crosses this boundary and must
# be authenticated (JWT) and transmitted over HTTPS/TLS.
boundary_internet = Boundary("Internet (Untrusted)")

# Boundary: Internet (Admin) — same logical zone as boundary_internet but
# kept as a separate object so Threat Dragon renders the Administrator in
# its own explicit boundary box, consistent with the Level 1 diagram.
boundary_internet_admin = Boundary("Internet (Untrusted) — Admin")

# Boundary: External Systems — where third-party systems that receive
# outbound data from the application live (ELK/SIEM).
# Outbound audit logs cross from the system into this boundary over HTTPS/TLS.
boundary_external = Boundary("External Systems")

# ─────────────────────────────────────────────────────────────────────────────
# EXTERNAL ENTITIES  —  Actor (rectangle in DFD)
# ─────────────────────────────────────────────────────────────────────────────

user = Actor("User (Browser / App)")
user.description = (
    "An end user interacting with the system via a browser or mobile REST "
    "client over HTTPS. May hold role OWNER, EDITOR or VIEWER on a given "
    "resource. Subject to StorageQuota and IsLocked account lockout."
)
user.inBoundary = boundary_internet

admin = Actor("Administrator")
admin.description = (
    "A privileged user who manages user accounts and system configuration "
    "via administrative endpoints. Authenticated by JWT with Admin role."
)
admin.inBoundary = boundary_internet_admin
admin.isAdmin = True

ext_log = Actor("External Log System (ELK / SIEM)")
ext_log.description = (
    "External log aggregation system receiving structured JSON audit events "
    "from the application in real time. Write-only, authenticated via API key "
    "over HTTPS/TLS. Provides immutable audit trail for non-repudiation."
)
ext_log.inBoundary = boundary_external

# ─────────────────────────────────────────────────────────────────────────────
# PROCESS  —  Server (circle / ellipse in DFD)
# At Level 0 the entire system is a single black-box process.
# Internal decomposition (Auth, File ops, Folder ops, RBAC, Audit, DB, FS)
# is shown in the Level 1 diagram (dfd_level1.py).
# ─────────────────────────────────────────────────────────────────────────────

system = Server("Secure File Management System")
system.description = (
    "The complete system as a black box. "
    "Internally: Spring Boot monolith handling authentication (JWT), "
    "file and folder operations (Java NIO / OS I/O), RBAC via AccessShare, "
    "persistence in PostgreSQL (JDBC), and structured audit logging. "
    "Decomposed in Level 1 DFD."
)
system.protocol = "HTTPS/TLS"
system.port = 443
system.tlsVersion = TLSVersion.TLSv13
system.usesSessionTokens = True

# ─────────────────────────────────────────────────────────────────────────────
# DATA FLOWS  —  Dataflow (arrow in DFD)
# At Level 0 flows are high-level — they represent categories of interaction,
# not individual API endpoints. Those are detailed in Level 1.
# ─────────────────────────────────────────────────────────────────────────────

# ── User → System : Requests ──────────────────────────────────────────────────
df01 = Dataflow(user, system, "User Requests (HTTPS/TLS)")
df01.description = (
    "All requests from the User to the system over HTTPS/TLS: "
    "authentication (login, register, refresh token), "
    "file operations (upload, download, delete), "
    "folder operations (create, list, rename, delete), "
    "and access management (share, revoke). "
    "All requests carry a JWT in the Authorization header "
    "(except login and register)."
)
df01.protocol = "HTTPS/TLS"
df01.tlsVersion = TLSVersion.TLSv13
df01.usesSessionTokens = True
df01.order = 1

# ── System → User : Responses ────────────────────────────────────────────────
df02 = Dataflow(system, user, "System Responses (HTTPS/TLS)")
df02.description = (
    "All responses from the system to the User over HTTPS/TLS: "
    "JWT tokens (on successful authentication), "
    "file content (served with Content-Disposition: attachment), "
    "JSON metadata responses, "
    "and generic error messages (never exposing internal details)."
)
df02.protocol = "HTTPS/TLS"
df02.tlsVersion = TLSVersion.TLSv13
df02.isResponse = True
df02.responseTo = df01
df02.usesSessionTokens = True
df02.order = 2

# ── Admin → System : Administrative requests ─────────────────────────────────
df03 = Dataflow(admin, system, "Admin Requests (HTTPS/TLS + JWT Admin role)")
df03.description = (
    "Administrative requests from the Administrator to the system: "
    "user account management (create, suspend, delete). "
    "Requires JWT with Admin role. "
    "Spring Boot Actuator restricted to internal network only in production."
)
df03.protocol = "HTTPS/TLS"
df03.tlsVersion = TLSVersion.TLSv13
df03.usesSessionTokens = True
df03.order = 3

# ── System → Admin : Administrative responses ─────────────────────────────────
df04 = Dataflow(system, admin, "Admin Responses (HTTPS/TLS)")
df04.description = (
    "Responses to administrative requests: confirmation of account operations, "
    "user listings, system status. "
    "All transmitted over HTTPS/TLS."
)
df04.protocol = "HTTPS/TLS"
df04.tlsVersion = TLSVersion.TLSv13
df04.isResponse = True
df04.responseTo = df03
df04.order = 4

# ── System → External Log System : Audit logs ────────────────────────────────
df05 = Dataflow(system, ext_log, "Structured Audit Logs (HTTPS/TLS)")
df05.description = (
    "Structured JSON audit log events forwarded from the system to the "
    "external ELK/SIEM in real time over HTTPS/TLS. "
    "Each event: timestamp, userId, action, resourceId, resourceType, sourceIP. "
    "Authenticated via API key. Logs not stored exclusively on local server — "
    "the external system provides the immutable audit trail."
)
df05.protocol = "HTTPS/TLS"
df05.tlsVersion = TLSVersion.TLSv13
df05.order = 5

# ─────────────────────────────────────────────────────────────────────────────
# PROCESS
# ─────────────────────────────────────────────────────────────────────────────
tm.process()