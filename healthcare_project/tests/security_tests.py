"""
security_tests.py
Executes 6 security tests against the live secure_ingest system and
captures real, reproducible evidence (not simulated).

Run:  python3 security_tests.py
Output: prints evidence to stdout AND writes tests/evidence.log
"""
import sys
import os
import shutil
import csv
import sqlite3
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from secure_ingest import (
    register_upload, ingest_file, verify_against_manifest, decrypt_record,
    sha256_file, DB_PATH, MANIFEST_DIR
)
from auth import authenticate, AuthError, authorize

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
DATA_DIR = os.path.join(BASE_DIR, "data")
EVIDENCE_LOG = os.path.join(os.path.dirname(__file__), "evidence.log")

results = []
_ev = open(EVIDENCE_LOG, "w")

def ev(line=""):
    print(line)
    _ev.write(str(line) + "\n")

def record_result(test_id, objective, procedure, expected, actual, passed):
    results.append({
        "test_id": test_id, "objective": objective, "procedure": procedure,
        "expected": expected, "actual": actual, "passed": passed
    })
    ev(f"\n=== {test_id}: {'PASS' if passed else 'FAIL'} ===")
    ev(f"Objective: {objective}")
    ev(f"Expected:  {expected}")
    ev(f"Actual:    {actual}")


# ---------------------------------------------------------------------------
# TEST 1: Data tampering detection - modify a registered file, confirm rejection
# ---------------------------------------------------------------------------
def test1_tamper_detection():
    src = os.path.join(DATA_DIR, "incoming_registered_sample.csv")
    # use one of the already-registered files, copy it fresh to simulate re-delivery attempt
    original = os.path.join(DATA_DIR, "incoming", "Clinic_Nairobi_A_20260718_0000.csv")
    tampered = os.path.join(DATA_DIR, "test1_tampered.csv")
    shutil.copy(original, tampered)
    manifest_src = os.path.join(MANIFEST_DIR, "Clinic_Nairobi_A_20260718_0000.csv.manifest.json")
    manifest_dst = os.path.join(MANIFEST_DIR, "test1_tampered.csv.manifest.json")
    with open(manifest_src) as f:
        manifest = json.load(f)
    manifest["filename"] = "test1_tampered.csv"
    with open(manifest_dst, "w") as f:
        json.dump(manifest, f)

    original_hash = sha256_file(tampered)

    # Attacker modifies one field in the file after it was "signed"
    with open(tampered, "r") as f:
        rows = list(csv.DictReader(f))
        fieldnames = list(rows[0].keys())
    rows[0]["diagnosis"] = "TAMPERED_VALUE_INJECTED"
    with open(tampered, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    new_hash = sha256_file(tampered)
    ok, detail = verify_against_manifest(tampered)

    actual = f"original_hash={original_hash[:16]}... new_hash={new_hash[:16]}... verify_result={ok}, detail='{detail}'"
    passed = (ok is False) and (original_hash != new_hash)
    record_result(
        "TEST-1", "Confirm the system detects and rejects a file altered after signing",
        "Copy a registered clinic file, modify a field, recompute integrity check",
        "verify_against_manifest() returns False with a hash-mismatch message; file not ingested",
        actual, passed
    )
    return passed


# ---------------------------------------------------------------------------
# TEST 2: Reject altered/unsigned files at ingestion (end-to-end via ingest_file)
# ---------------------------------------------------------------------------
def test2_reject_at_ingestion():
    tampered = os.path.join(DATA_DIR, "test1_tampered.csv")
    result = ingest_file(tampered, "clinic_nairobi_a", "ClinicUpload!99")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM patients WHERE source_file='test1_tampered.csv'")
    stored_count = cur.fetchone()[0]
    conn.close()

    actual = f"ingest_file() result={result}, records stored under this filename={stored_count}"
    passed = (result["status"] == "rejected") and (stored_count == 0)
    record_result(
        "TEST-2", "Confirm tampered files are rejected end-to-end and never reach storage",
        "Call ingest_file() on the tampered file from TEST-1 using valid clinic credentials",
        "Ingestion pipeline rejects the file before any records are written to the database",
        actual, passed
    )
    return passed


# ---------------------------------------------------------------------------
# TEST 3: Authentication - invalid credentials must be rejected
# ---------------------------------------------------------------------------
def test3_invalid_auth():
    try:
        authenticate("clinic_nairobi_a", "WrongPassword123")
        auth_failed_as_expected = False
        err_msg = "no exception raised"
    except AuthError as e:
        auth_failed_as_expected = True
        err_msg = str(e)

    try:
        authenticate("nonexistent_user", "whatever")
        unknown_user_rejected = False
    except AuthError:
        unknown_user_rejected = True

    actual = f"wrong_password -> AuthError raised: {auth_failed_as_expected} ('{err_msg}'); unknown_user -> rejected: {unknown_user_rejected}"
    passed = auth_failed_as_expected and unknown_user_rejected
    record_result(
        "TEST-3", "Confirm the system rejects invalid credentials and unknown accounts",
        "Call authenticate() with a wrong password for a real user, and with a nonexistent username",
        "AuthError raised in both cases; no session/token issued",
        actual, passed
    )
    return passed


# ---------------------------------------------------------------------------
# TEST 4: Role-Based Access Control - clinic_uploader must NOT be able to decrypt records
# ---------------------------------------------------------------------------
def test4_rbac_enforcement():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT record_id FROM patients LIMIT 1")
    record_id = cur.fetchone()[0]
    conn.close()

    # clinic_uploader tries to decrypt - should fail (not authorized)
    uploader_blocked = False
    try:
        decrypt_record(record_id, "clinic_nairobi_a", "ClinicUpload!99")
    except AuthError:
        uploader_blocked = True

    # auditor tries to decrypt - should also fail (auditor has view_logs only, not decrypt)
    auditor_blocked = False
    try:
        decrypt_record(record_id, "compliance_auditor", "AuditView!2026")
    except AuthError:
        auditor_blocked = True

    # admin should succeed
    admin_data = decrypt_record(record_id, "hospital_admin", "AdminPass!2026")
    admin_succeeded = admin_data is not None and "diagnosis" in admin_data

    actual = (f"clinic_uploader decrypt blocked={uploader_blocked}, "
              f"auditor decrypt blocked={auditor_blocked}, "
              f"admin decrypt succeeded={admin_succeeded}")
    passed = uploader_blocked and auditor_blocked and admin_succeeded
    record_result(
        "TEST-4", "Confirm role-based access control restricts decryption to the admin role only",
        "Attempt decrypt_record() as clinic_uploader, auditor, and admin roles",
        "clinic_uploader and auditor are denied (AuthError); admin succeeds",
        actual, passed
    )
    return passed


# ---------------------------------------------------------------------------
# TEST 5: Encryption at rest - raw DB bytes must not contain plaintext PII
# ---------------------------------------------------------------------------
def test5_encryption_at_rest():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT record_id, encrypted_blob FROM patients LIMIT 200")
    rows = cur.fetchall()
    conn.close()

    # Known plaintext values we injected: first/last names, diagnoses used in generator
    probe_terms = [b"Mwangi", b"Hypertension", b"Malaria", b"Otieno", b"Wanjiru"]
    leaked = []
    for record_id, blob in rows:
        for term in probe_terms:
            if term in blob:
                leaked.append((record_id, term))

    actual = f"Scanned {len(rows)} encrypted blobs for {len(probe_terms)} known plaintext terms. Matches found: {len(leaked)}"
    passed = len(leaked) == 0
    record_result(
        "TEST-5", "Confirm patient data is encrypted at rest (no plaintext PII visible in DB storage)",
        "Read raw encrypted_blob bytes directly from SQLite and search for known plaintext substrings",
        "Zero plaintext matches - all values must be unrecoverable without the encryption key",
        actual, passed
    )
    return passed


# ---------------------------------------------------------------------------
# TEST 6: Audit logging completeness - every ingestion attempt (success + failure) is logged
# ---------------------------------------------------------------------------
def test6_audit_logging():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT status, COUNT(*) FROM upload_log GROUP BY status")
    status_counts = dict(cur.fetchall())
    cur.execute("SELECT COUNT(*) FROM upload_log WHERE status='SUCCESS'")
    success_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM upload_log WHERE status LIKE 'REJECTED%'")
    rejected_count = cur.fetchone()[0]
    conn.close()

    log_file_exists = os.path.exists(os.path.join(BASE_DIR, "logs", "ingestion.log"))
    with open(os.path.join(BASE_DIR, "logs", "ingestion.log")) as f:
        line_count = sum(1 for _ in f)

    actual = (f"upload_log status breakdown={status_counts}; "
              f"success_events={success_count}, rejected_events={rejected_count}; "
              f"logs/ingestion.log exists={log_file_exists} with {line_count} lines")
    passed = success_count > 0 and rejected_count > 0 and log_file_exists
    record_result(
        "TEST-6", "Confirm every upload attempt (successful and rejected) is captured in the audit log",
        "Query the upload_log table and the ingestion.log file after running tests 1-5",
        "Log contains both SUCCESS and REJECTED_* entries with timestamps and actor identity",
        actual, passed
    )
    return passed


if __name__ == "__main__":
    ev("SECURITY TEST EXECUTION LOG")
    ev("=" * 70)
    t1 = test1_tamper_detection()
    t2 = test2_reject_at_ingestion()
    t3 = test3_invalid_auth()
    t4 = test4_rbac_enforcement()
    t5 = test5_encryption_at_rest()
    t6 = test6_audit_logging()

    ev("\n" + "=" * 70)
    ev("SUMMARY")
    for r in results:
        ev(f"  {r['test_id']}: {'PASS' if r['passed'] else 'FAIL'} - {r['objective']}")
    total_pass = sum(1 for r in results if r["passed"])
    ev(f"\n{total_pass}/{len(results)} tests passed")

    with open(os.path.join(os.path.dirname(__file__), "test_results.json"), "w") as f:
        json.dump(results, f, indent=2)

    _ev.close()
