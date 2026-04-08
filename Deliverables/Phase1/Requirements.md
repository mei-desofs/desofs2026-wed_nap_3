# System Requirements

This document outlines the Functional, Non-Functional, and Secure Development Requirements for the "Ender Chest" system. The MoSCoW prioritization method (Must, Should, Could, Won't) is used to indicate the priority of each requirement.

## Functional Requirements (FR)

| ID | Description | Priority |
| :--- | :--- | :--- |
| **FR-01** | The system must allow users to upload files to the server, with strict validation of file type and size. | MUST |
| **FR-02** | The system must allow users to download files to which they have authorized access. | MUST |
| **FR-03** | The system must allow users to create, list, rename, and delete folders/directories on the server. | MUST |
| **FR-04** | The owner of a file (Owner) can share files with other users by assigning them a specific role (Editor or Viewer). | MUST |
| **FR-05** | The system must support three roles: Owner (full control), Editor (upload/edit), and Viewer (read-only). | MUST |
| **FR-06** | The Owner must be able to revoke access from other users at any given time. | MUST |
| **FR-07** | The system must expose a REST API for all operations concerning files and folders. | MUST |
| **FR-08** | The system should maintain an audit log of all actions performed (upload, download, sharing, deletion). | SHOULD |
| **FR-09** | Users must be able to register, authenticate, and manage their profiles. | MUST |

## Non-Functional Requirements (NFR)

| ID | Description | Priority |
| :--- | :--- | :--- |
| **NFR-01** | All communication between the client and the server must be conducted over HTTPS/TLS. | MUST |
| **NFR-02** | The system must run as a Spring Boot application utilizing a persistent relational database (e.g., PostgreSQL). | MUST |
| **NFR-03** | The code architecture must follow Domain-Driven Design (DDD) principles with at least three aggregates (e.g., User, File, Folder). | MUST |
| **NFR-04** | The system should record error and access logs in a structured format (e.g., JSON logs). | SHOULD |
| **NFR-05** | The application should be containerizable (Docker) to facilitate deployment and CI/CD pipelines. | SHOULD |

## Secure Development Requirements (SDR)

| ID | Description | Priority |
| :--- | :--- | :--- |
| **SDR-01** | Authentication via JWT (JSON Web Token) with an expiration time and a refresh token mechanism. | MUST |
| **SDR-02** | Role-Based Access Control (RBAC) - access to each resource must be strictly verified before any operation is executed. | MUST |
| **SDR-03** | Strict validation and sanitization of all inputs received by the API (filenames, paths, MIME types). | MUST |
| **SDR-04** | Path Traversal prevention — file paths must be normalized and strictly confined to the system's base storage directory. | MUST |
| **SDR-05** | Limitation of the size and type of files accepted during upload to prevent Denial of Service (DoS) attacks. | MUST |
| **SDR-06** | Passwords must be stored using a secure cryptographic hash (BCrypt or Argon2) — never in plaintext. | MUST |
| **SDR-07** | Third-party dependencies should be managed with SCA (Software Composition Analysis, e.g., OWASP Dependency-Check) and updated regularly. | SHOULD |
| **SDR-08** | Static Application Security Testing (SAST) integrated into the CI/CD pipeline (e.g., SonarQube, Semgrep). | SHOULD |
| **SDR-09** | Secure server configuration — HTTP security headers (CSP, HSTS, X-Frame-Options) must be active by default. | MUST |
| **SDR-10** | Implementation of rate limiting on API endpoints to mitigate brute force and DDoS attacks. | MUST |