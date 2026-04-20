# Ender Chest – Secure File Manager

## Team

| Element | Name     | Student ID |
| ------- | -------- | ---------- |
| 1       | Tiago Queirós | 1210910   |
| 2       | Pedro Conceição | 1211018   |
| 3       | Tiago Silva | 1250554   |
| 4       | Gonçalo Costa | 1201062   |
> Please edit this table to include your real names and student IDs.

## Overview

**Ender Chest** is a secure, auditable file management system developed as the course project for **DESOFS 2026** (Development of Secure Software) at MEI. The system offers core file server capabilities—including upload, download, RBAC-based sharing, and audit logging—with a strong focus on secure architecture and defensive programming to mitigate classic vulnerabilities (path traversal, DoS, unauthorized access, etc).

## Features

- Secure file upload and download via a RESTful API
- Folder management: create, rename, delete, list
- Share files and folders using roles: **Owner** (full), **Editor** (edit/upload), **Viewer** (read-only)
- Audit log for all critical actions (upload, download, share, delete)
- Enforced RBAC and strong authentication (JWT with refresh)
- File storage split: metadata in relational DB (PostgreSQL), binaries on host FS
- Protection against path traversal, malicious file uploads, brute force, and DDoS
- Defensive coding and SSDLC best practices

## Repository Structure

```text
/
├── Deliverables/
│   └── Phase1/
│       ├── Main_Document.md
│       ├── System_Overview.md
│       ├── Requirements.md
│       ├── *.mmd              
│       └── ../assets/        
│       └── ...   
├── src/
│   └── ...                    
├── tests/
│   └── ...                  
├── README.md
└── LICENSE
