# Secure Healthcare Data Collection - Group 1

## Quick start
```
cd scripts
python3 db_init.py          # creates storage/hospital.db + demo RBAC users
python3 generate_dataset.py # generates 120,000 synthetic records (12 clinic batches)
python3 run_ingestion.py    # registers, hashes, signs, encrypts, and stores all batches
cd ../tests
python3 security_tests.py   # runs the 6 security tests, writes evidence.log + test_results.json
```

## Demo accounts (seeded by db_init.py)
| username | password | role |
|---|---|---|
| hospital_admin | AdminPass!2026 | admin |
| clinic_nairobi_a | ClinicUpload!99 | clinic_uploader |
| compliance_auditor | AuditView!2026 | auditor |

## Requirements
Python 3.10+, `cryptography` package (`pip install cryptography`).

See the accompanying report (Group1_Secure_Healthcare_Data_Collection_Report.docx)
for full documentation of environment design, security controls, test evidence,
and recommendations.
