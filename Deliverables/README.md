# EnderChest — Project Deliverables

**Course:** DESOFS 2026
**Group:** WED_NAP_3
**Repository:** `desofs2026-wed_nap_3`

---

## Overview

**EnderChest** is a secure file-storage application built following a DevSecOps methodology across two phases. Phase 1 covered secure analysis and design; Phase 2 covered secure development, testing, and production deployment. This index consolidates every deliverable produced in each phase and sprint.

| Phase | Focus | Period |
|:------|:------|:-------|
| **Phase 1** | Analysis & Secure Design | Mar – Apr 2026 |
| **Phase 2 · Sprint 1** | Development, Security Testing & CI/CD | May 2026 |
| **Phase 2 · Sprint 2** | Deployment, Observability & Gap Closure | June 2026 |

---

## Phase 1 — Analysis & Secure Design

**Location:** [`Phase1/`](./Phase1/)

The design phase established the security requirements, threat model, and verification baseline for the application.

| Deliverable | Description |
|:------------|:------------|
| [Main_Document.md](./Phase1/Main_Document.md) | Consolidated Phase 1 report |
| [System_Overview.md](./Phase1/System_Overview.md) | System context and goals |
| [Requirements.md](./Phase1/Requirements.md) | Functional and security requirements |
| [Architecture_Diagram.mmd](./Phase1/Architecture_Diagram.mmd) | System architecture |
| [Domain_model.mmd](./Phase1/Domain_model.mmd) | Domain model |
| [DFDs.md](./Phase1/DFDs.md) | Data Flow Diagrams (Levels 0–2) |
| [Threat_modeling.md](./Phase1/Threat_modeling.md) | STRIDE threat model |
| [Abuses_Cases.md](./Phase1/Abuses_Cases.md) | Abuse / misuse cases |
| [Risk_Assessment.md](./Phase1/Risk_Assessment.md) | Risk assessment |
| [Security_Testing.md](./Phase1/Security_Testing.md) | Security testing strategy |
| [ASVS_Checklist.md](./Phase1/ASVS_Checklist.md) | ASVS verification checklist |

---

## Phase 2 — Secure Development & Operations

**Shared artifacts:** [`Phase2/`](./Phase2/)

| Deliverable | Description |
|:------------|:------------|
| [Pipeline_Decisions.md](./Phase2/Pipeline_Decisions.md) | Rationale for each CI/CD pipeline job |
| [PipelineStructure.mmd](./Phase2/PipelineStructure.mmd) | CI/CD pipeline diagram |
| [ASVS_5.0_Tracker_filled.xlsx](./Phase2/ASVS_5.0_Tracker_filled.xlsx) | ASVS v5.0 verification tracker |

### Sprint 1 — Development & Security Testing

**Location:** [`Phase2/Sprint1/`](./Phase2/Sprint1/)

Delivered the secure application core, automated security testing, and the CI/CD pipeline.

| Deliverable | Description |
|:------------|:------------|
| [README.md](./Phase2/Sprint1/README.md) | Sprint 1 deliverables index |
| [SPRINT1_REPORT.md](./Phase2/Sprint1/SPRINT1_REPORT.md) | Full Sprint 1 report |

**Highlights:**
- OAuth2 / Auth0 authentication with role-based `@PreAuthorize` authorization
- File storage security: SHA-256 hashing, magic-byte validation, path-traversal prevention, per-user quota
- IDOR prevention via object-level access control
- 53 automated security tests (RBAC, IDOR, upload security)
- CI/CD pipeline: Build & Test, Gitleaks, OWASP Dependency-Check (SCA), SonarCloud (SAST), Trivy (container scan)

### Sprint 2 — Deployment, Observability & Gap Closure

**Location:** [`Phase2/Sprint2/`](./Phase2/Sprint2/)

Delivered the hardened production deployment, centralized audit logging, and closure of Sprint 1 gaps.

| Deliverable | Description |
|:------------|:------------|
| [README.md](./Phase2/Sprint2/README.md) | Sprint 2 deliverables index & gap-closure report |
| [DEPLOYMENT_REPORT.md](./Phase2/Sprint2/DEPLOYMENT_REPORT.md) | Production deployment architecture (K3s, Helm, TLS, ELK) |

**Highlights:**
- Production deployment to a K3s cluster on Azure via Helm
- DAST (OWASP ZAP) integrated into the CI pipeline
- Centralized audit logging (Elasticsearch + Kibana + Filebeat) — satisfies SDR-NEW-03
- Structured JSON logging via Logstash encoder (prod profile)
- Rate-limiting integration tests (HTTP 429 enforcement)
- New service-layer unit tests (Folder, User, AccessShare)
- TLS via Traefik's built-in Let's Encrypt ACME
- Health monitoring via Spring Boot Actuator + Kubernetes probes

---

## Capability Map

| Capability | Phase / Sprint |
|:-----------|:---------------|
| Threat model & secure design | Phase 1 |
| Authentication & authorization | P2 · Sprint 1 |
| File storage security controls | P2 · Sprint 1 |
| Automated security testing (SAST/SCA) | P2 · Sprint 1 |
| CI/CD pipeline | P2 · Sprint 1 |
| DAST (OWASP ZAP) | P2 · Sprint 2 |
| Centralized audit logging (ELK) | P2 · Sprint 2 |
| Structured logging | P2 · Sprint 2 |
| Rate-limiting tests | P2 · Sprint 2 |
| Production deployment + TLS | P2 · Sprint 2 |
| SonarCloud quality-gate enforcement | P2 · Sprint 2 |
| ASVS v5.0 tracker | P2 · Sprint 2 |

---

## Technology Stack

| Layer | Technology |
|:------|:-----------|
| Application | Java 21, Spring Boot, Spring Security (OAuth2) |
| Persistence | PostgreSQL 16, Spring Data JPA |
| Auth | Auth0 (RS256 JWT) |
| Build | Maven |
| Security Testing | SonarCloud (SAST), OWASP Dependency-Check (SCA), Trivy, Gitleaks, OWASP ZAP (DAST) |
| Packaging | Docker, Helm |
| Orchestration | K3s (Kubernetes) on Azure |
| Ingress / TLS | Traefik + Let's Encrypt |
| Observability | Elasticsearch, Kibana, Filebeat (ELK) |

---

**Last Updated:** June 16, 2026
