# System Overview & High-Level Architecture

## System Overview
**Ender Chest** is a Secure File Management System developed in Java (Spring Boot). The main goal of the system is not functional complexity, but rather resilience against attacks and the strict implementation of SSDLC practices.

As per the project requirements, the system executes direct operations on the server's Operating System (directory creation, reading, and writing of binary files). **These operations are strictly triggered by user inputs** (upload, download, and folder creation requests via the API).

To address scenarios of successful exploitation, the system relies on a strong damage mitigation strategy:
1. **Detection:** Implementation of an immutable Audit Logging system that records who accessed, modified, or shared resources.
2. **Damage Reduction:** Enforcement of the *Least Privilege* principle (Role-Based Access Control with Owner, Editor, and Viewer roles). This ensures that a compromised user only affects their own scope (using logical *chroot* confinement to prevent *Path Traversal*).
3. **Repair:** Preservation of secure states that allow for the recovery of corrupted or lost data (e.g., soft deletes or versioning).

## High-Level Architecture
The architecture follows a secure Client-Server model:
* **Presentation Layer (Client):** Consumes the REST API strictly via HTTPS/TLS to prevent data interception (*Man-in-the-Middle* attacks).
* **API Gateway / Security Layer:** Inspects all user input. Validates JWT tokens, sanitizes file paths, and applies *Rate Limiting*.
* **Application Layer (Spring Boot):** Business logic is strictly encapsulated using *Domain-Driven Design* (DDD) principles.
* **Persistence Layer (PostgreSQL & OS File System):** Strict separation between metadata (stored in the relational database) and the physical files. Access to the file system is mediated by a dedicated service that prevents directory traversal outside the secure base directory.