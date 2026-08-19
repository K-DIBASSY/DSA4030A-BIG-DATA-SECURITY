# Secure Healthcare Data Collection

**DSA 4030: Big Data Security — End of Semester Practical Group Project**
Summer Semester 2026 — Group 3

## Overview

A hardened data-ingestion pipeline that lets five simulated clinic sites across Kenya push hourly patient-record batches into a central system. Every file is authenticated, integrity-checked, encrypted, and audited before it becomes queryable data.

## Why It Matters

Health records are highly sensitive. The system answers three questions for every incoming file:
- Is the sender genuine?
- Has the file been altered?
- Can every action be proven after the fact?

## Architecture — Five Gates Every File Passes Through

1. **Clinic Upload** — Hourly CSV batch arrives with a signed manifest
2. **Authenticate & Authorize** — Credentials and role permissions checked (`auth.py`)
3. **Verify Integrity** — SHA-256 hash + HMAC signature checked against the manifest
4. **Encrypt & Store** — Each record encrypted with Fernet (AES-128-CBC + HMAC)
5. **Audit Log** — Every attempt, success or rejection, written to database and file

A file failing steps 2 or 3 is rejected outright and quarantined — it never reaches encryption or storage.

## Security Controls

- **Auth + RBAC:** PBKDF2-HMAC-SHA256 (200,000 iterations); three roles — `admin`, `clinic_uploader`, `auditor` — each scoped so only admin can decrypt patient data
- **Tamper Rejection:** Hash/signature mismatches are caught and quarantined before ingestion
- **Encryption at Rest:** Every record encrypted individually; no plaintext PII on disk
- **Dual-Channel Audit Logging:** A queryable SQLite table plus a human-readable append-only log

## Validation — 6/6 Tests Passed

Tamper detection, end-to-end rejection, invalid-authentication handling, RBAC enforcement, encryption verification (0 of 200 scanned blobs leaked plaintext), and audit completeness (13 successes, 1 rejection, all logged).

## Requirements

| Component | Purpose |
|---|---|
| Python 3.10+ | Application runtime |
| SQLite | Local storage of encrypted records, audit logs, integrity data |
| `cryptography` | Fernet symmetric encryption/decryption |
| `hashlib`, `hmac`, `csv`, `json`, `sqlite3` | Standard library — hashing, signing, data handling |

Install the one third-party dependency:

```bash
pip install cryptography
# or
pip install -r requirements.txt
```

## Project Structure

```
project/
|
+-- data/
|   +-- incoming/
|   +-- manifests/
|   +-- quarantine/
|
+-- logs/
|   +-- ingestion.log
|
+-- storage/
|   +-- hospital.db
|   +-- encryption.key
|   +-- hmac.key
|
+-- src/
|   +-- generate_dataset.py
|   +-- secure_ingest.py
|   +-- auth.py
|   +-- simulate_uploads.py
|
+-- requirements.txt
```

## Getting Started

1. Initialize the database: `db_init.py` creates the schema and three demo accounts (admin, clinic_uploader, auditor).
2. Generate synthetic data: `generate_dataset.py` produces 120,000 synthetic records across 12 hourly batches from 5 simulated clinics.
3. Run ingestion: `simulate_uploads.py` registers and ingests every file in `data/incoming`.
4. Run tests: `security_tests.py` runs the 6 automated security checks.

## Demo Accounts (for testing only)

| Username | Role |
|---|---|
| hospital_admin | admin |
| clinic_nairobi_a | clinic_uploader |
| compliance_auditor | auditor |

*These are demonstration credentials only and must be replaced before any real deployment.*

## Known Risks & Recommended Next Steps

This is a tested prototype, not a production system. Key items before production deployment:

- Move encryption/HMAC keys to a managed KMS/HSM or OS keyring
- Add TLS/SFTP with mutual authentication for clinic-to-hospital transfer
- Issue unique per-user credentials with MFA and rate-limiting
- Migrate from SQLite to a managed database with encrypted backups
- Make the audit log tamper-evident (hash-chaining) and forward to a SIEM
- Upgrade to AES-256-GCM where required by policy

See the full report for the detailed risk register and rationale.

## Contributors

- Kemo Dibassy
- Angel Musomba
- Valerian Murago
