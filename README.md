# MedSecure Vulnerable App

A minimal Java Spring Boot web application simulating a healthcare SaaS backend. This repository contains **deliberately planted security vulnerabilities** for use as a target in the MedSecure CodeQL Remediation Pipeline demo.

> **WARNING**: This application contains intentional security flaws. Do not deploy to any production or internet-facing environment.

## Planted Vulnerabilities

| # | Vulnerability | File | CodeQL Rule |
|---|---|---|---|
| 1 | SQL Injection | `PatientController.java` | `java/sql-injection` |
| 2 | Path Traversal | `FileController.java` | `java/path-injection` |
| 3 | Hardcoded Credentials | `SecurityConfig.java` | `java/hardcoded-credential-api-call` |
| 4 | Sensitive Data in Logs | `PatientService.java` | `java/sensitive-log` |
| 5 | Weak Cryptographic Algorithm (MD5) | `EncryptionService.java` | `java/weak-cryptographic-algorithm` |

## Project Structure

```
src/main/java/com/medsecure/app/
├── MedSecureApplication.java        # Spring Boot entry point
├── config/
│   └── SecurityConfig.java          # Authentication & authorization
├── controller/
│   ├── PatientController.java       # Patient REST API
│   └── FileController.java          # File download endpoint
├── service/
│   ├── PatientService.java          # Patient business logic
│   └── EncryptionService.java       # Data hashing utilities
├── repository/
│   └── PatientRepository.java       # JPA data access
└── model/
    └── Patient.java                 # Patient entity
```

## Prerequisites

- Java 17+
- Maven 3.8+

## Build

```bash
mvn compile
```

The application does not need to run — it only needs to compile for CodeQL analysis.

## CodeQL Scanning

A GitHub Actions workflow (`.github/workflows/codeql-analysis.yml`) runs CodeQL analysis automatically on:
- Every push to `main`
- Every pull request targeting `main`

Results are uploaded as SARIF to GitHub Code Scanning and can be viewed in the repository's **Security → Code scanning alerts** tab.

## CODEOWNERS

The `.github/CODEOWNERS` file maps source paths to responsible owners:
- `config/` → `@security-team-lead`
- `controller/`, `service/` → `@backend-lead`
- `repository/`, `model/` → `@data-lead`
- `.github/` → `@devops-lead`

These owners are used by the remediation agent to auto-assign fix PRs.
