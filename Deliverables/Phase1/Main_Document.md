# Ender Chest — Phase 1 (Analysis & Secure Design)

**Course:** DESOFS 2026  
**Group:** WED_NAP_3  
**Repository:** `desofs2026_wed_nap_3`  
**Phase:** 1  
**Last updated:** YYYY-MM-DD  

---

## Table of Contents
- [Document Control (Versioning)](#document-control-versioning)
- [Team](#team)
- [1. Introduction](#1-introduction)
  - [1.1 Project Summary](#11-project-summary)
  - [1.2 Goals](#12-goals)
  - [1.3 Assumptions and Constraints](#13-assumptions-and-constraints)
- [2. Deliverables Index (Phase 1)](#2-deliverables-index-phase-1)
  - [2.1 System Overview & Architecture](#21-system-overview--architecture)
  - [2.2 Domain Model (DDD)](#22-domain-model-ddd)
  - [2.3 Requirements](#23-requirements)
  - [2.4 Data Flow Diagrams (DFD) and Trust Boundaries (Element 2)](#24-data-flow-diagrams-dfd-and-trust-boundaries-element-2)
  - [2.5 Threat Modeling (STRIDE) (Element 2)](#25-threat-modeling-stride-element-2)
  - [2.6 Abuse Cases (Element 3)](#26-abuse-cases-element-3)
  - [2.7 Risk Assessment (Element 3)](#27-risk-assessment-element-3)
  - [2.8 Secure Development Practices (SSDLC) and Controls (Element 1 + Team)](#28-secure-development-practices-ssdlc-and-controls-element-1--team)
  - [2.9 Security Testing Plan / ASVS Mapping (Element 4)](#29-security-testing-plan--asvs-mapping-element-4)
- [3. Phase 1 Summary](#3-phase-1-summary)
  - [3.1 Main Security Risks (Summary)](#31-main-security-risks-summary)
  - [3.2 Key Mitigations (Summary)](#32-key-mitigations-summary)
  - [3.3 Open Issues / Pending Work](#33-open-issues--pending-work)
- [Appendix A — Naming Conventions](#appendix-a--naming-conventions)
- [Appendix B — Review Checklist (Leader Use)](#appendix-b--review-checklist-leader-use)

---

## Document Control (Versioning)

> This section is maintained by the team.  
> Add a new entry for every meaningful change to the Phase 1 deliverables (new document, major revision, threat model updates, etc.).

| Version | Date (YYYY-MM-DD) | Author(s) | Summary of Changes |
| :-- | :-- | :-- | :-- |
| 0.1 | YYYY-MM-DD | <name> | Initial structure created. |
| 0.2 | YYYY-MM-DD | <name> | Added requirements and system overview links. |
| 0.3 | YYYY-MM-DD | <name> | Added DFDs and threat model. |
| 1.0 | YYYY-MM-DD | <name> | Phase 1 final review and submission-ready. |

---

## Team

| Element | Name | Student ID |
| :-- | :-- | :-- |
| 1 | <name> | <id> |
| 2 | <name> | <id> |
| 3 | <name> | <id> |
| 4 | <name> | <id> |

---

## 1. Introduction

### 1.1 Project Summary
Describe the Ender Chest project in 5–8 lines: purpose, main features, and why security is critical.

### 1.2 Goals
- Secure file upload/download and folder management
- Sharing with RBAC (Owner/Editor/Viewer)
- Auditability and traceability of actions
- Resilience: reduce impact of mistakes or malicious actions (e.g., soft delete, versioning/rollback)

### 1.3 Assumptions and Constraints
- Authentication mechanism (e.g., JWT + refresh token)
- Storage approach: DB for metadata; OS file system for binary content
- Deployment assumptions (Docker, single-host, etc.)
- Out of scope items (if any)

---

## 2. Deliverables Index (Phase 1)

> All deliverables should live under `Deliverables/Phase1/`.  
> This section must be kept up to date and should be the “entry point” for the evaluator.

### 2.1 System Overview & Architecture

#### 2.1.1 Purpose and Scope
Ender Chest is a secure file management system that allows users to upload, download, organize, and share files and folders through a REST API. The system must execute OS-level actions (directory creation and file I/O) triggered by user requests, therefore secure design and authorization boundaries are central to the architecture.

#### 2.1.2 Physical Architecture (Deployment View)
This diagram shows the physical deployment: a REST client communicating with a Spring Boot backend over HTTPS. The backend persists metadata and access control information in PostgreSQL and stores binary content on the host file system. OS-level actions are executed by the backend using Java NIO.

![Physical Architecture Diagram](../assests/architecture_diagram.png)

#### 2.1.3 Domain Model (DDD View)
The domain model is organized around DDD aggregates. Authorization (RBAC / least privilege) and damage-reduction mechanisms (soft delete and file versioning/rollback) are represented explicitly in the model.

![Domain Model Diagram](../assests/domain_model.png)

#### 2.1.4 Key Security and Design Notes
- **Separation of responsibilities:** the database stores metadata (users, permissions, file/folder records), while the OS file system stores binary file contents.
- **Authorization first:** access checks are performed before any OS-level file operation.
- **Path traversal prevention by design:** physical storage paths are derived from safe identifiers (e.g., UUIDs) and restricted to a configured base directory.
- **Damage reduction:** soft delete and file version history reduce the impact of accidental or malicious destructive actions.

### 2.2 Domain Model (DDD)
- **Domain Model Mermaid (optional):** `Domain_Model.mmd`

### 2.3 Requirements
- **Requirements:** `Requirements.md`

### 2.4 Data Flow Diagrams (DFD) and Trust Boundaries (Element 2)
- **DFD Level 0:** `<add path>`
- **DFD Level 1:** `<add path>`
- **Trust Boundaries Notes:** `<add path>`

### 2.5 Threat Modeling (STRIDE) (Element 2)
- **Threat Model (STRIDE):** `<add path>`
- **Threat Mitigations (summary):** `<add path or section reference>`

### 2.6 Abuse Cases (Element 3)
- **Abuse Cases:** `<add path>`

### 2.7 Risk Assessment (Element 3)
- **Risk Assessment:** `<add path>`

### 2.8 Secure Development Practices (SSDLC) and Controls (Element 1 + Team)
- **Secure Development Requirements (if separate):** `<add path or keep inside Requirements.md>`
- **Security Controls Summary:** `<add path or section reference>`

### 2.9 Security Testing Plan / ASVS Mapping (Element 4)
- **Security Testing Plan:** `<add path>`
- **ASVS Checklist/Mapping:** `<add path>`

---

## 3. Phase 1 Summary

### 3.1 Main Security Risks (Summary)
Briefly list the top risks discovered (e.g., path traversal, IDOR, broken access control, malicious file uploads, DoS via large uploads).

### 3.2 Key Mitigations (Summary)
Summarize what the architecture and requirements enforce (RBAC, input validation, UUID-based storage paths, audit logging, rate limiting, etc.).

### 3.3 Open Issues / Pending Work
List anything still pending before Phase 1 submission.

---

## Appendix A — Naming Conventions

- Requirements IDs: `FR-xx`, `NFR-xx`, `SDR-xx`
- Diagram filenames: `architecture_diagram.png`, `domain_model.png`
- Phase 1 documents: `System_Overview.md` *(Note: contents moved to section 2.1)*, `Requirements.md`, `Main_Document.md`

---

## Appendix B — Review Checklist (Leader Use)

- [ ] All required deliverables exist in `Deliverables/Phase1/`
- [ ] All links and image paths render correctly on GitHub
- [ ] Requirements match domain model and architecture decisions
- [ ] Roles and authorization rules are consistent across all docs
- [ ] Threat model items map to mitigations and testing plan
- [ ] No broken diagrams / no missing references