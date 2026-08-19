"""
secure_ingest.py
Secure ingestion pipeline for hourly clinic uploads.

Security controls implemented here:
  1. Authentication + RBAC        (auth.py)
  2. File integrity verification  (SHA-256 hash + HMAC-SHA256 signature)
  3. Tamper rejection              (any file whose hash/signature doesn't match is rejected)
  4. Encryption at rest            (Fernet/AES-128-CBC+HMAC via `cryptography`)
  5. Full audit logging            (every attempt, success or failure, is logged)
"""
import os
import sqlite3
import hashlib
import hmac
import csv
import json
from datetime import datetime, timezone
from cryptography.fernet import Fernet

from auth import authenticate, require_permission, AuthError

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
DB_PATH = os.path.join(BASE_DIR, "storage", "hospital.db")
KEY_PATH = os.path.join(BASE_DIR, "storage", "encryption.key")
HMAC_KEY_PATH = os.path.join(BASE_DIR, "storage", "hmac.key")
QUARANTINE_DIR = os.path.join(BASE_DIR, "data", "quarantine")
MANIFEST_DIR = os.path.join(BASE_DIR, "data", "manifests")
LOG_PATH = os.path.join(BASE_DIR, "logs", "ingestion.log")

os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(MANIFEST_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------
def _load_or_create_key(path: str, keygen) -> bytes:
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    key = keygen()
    with open(path, "wb") as f:
        f.write(key)
    os.chmod(path, 0o600)
    return key


def get_fernet() -> Fernet:
    key = _load_or_create_key(KEY_PATH, Fernet.generate_key)
    return Fernet(key)


def get_hmac_key() -> bytes:
    return _load_or_create_key(HMAC_KEY_PATH, lambda: os.urandom(32))


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log_event(actor: str, action: str, filename: str, status: str, detail: str = ""):
    timestamp = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO upload_log (timestamp, actor, action, filename, status, detail) "
        "VALUES (?,?,?,?,?,?)",
        (timestamp, actor, action, filename, status, detail),
    )
    conn.commit()
    conn.close()

    with open(LOG_PATH, "a") as f:
        f.write(f"{timestamp} | actor={actor} | action={action} | "
                 f"file={filename} | status={status} | detail={detail}\n")


# ---------------------------------------------------------------------------
# Integrity: hashing + HMAC signing
# ---------------------------------------------------------------------------
def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_manifest(filename: str, file_hash: str) -> str:
    """Create an HMAC signature over filename+hash so the manifest itself can't be forged."""
    key = get_hmac_key()
    message = f"{filename}:{file_hash}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def write_manifest(filename: str, file_hash: str, signature: str):
    """Simulates the clinic sending a signed manifest alongside the data file."""
    manifest = {"filename": filename, "sha256": file_hash, "hmac": signature}
    manifest_path = os.path.join(MANIFEST_DIR, filename + ".manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    return manifest_path


def verify_against_manifest(filepath: str) -> tuple[bool, str]:
    """Recompute hash+signature and compare against the stored manifest. Rejects on mismatch."""
    filename = os.path.basename(filepath)
    manifest_path = os.path.join(MANIFEST_DIR, filename + ".manifest.json")

    if not os.path.exists(manifest_path):
        return False, "No manifest found for file - cannot verify integrity"

    with open(manifest_path) as f:
        manifest = json.load(f)

    current_hash = sha256_file(filepath)
    if current_hash != manifest["sha256"]:
        return False, f"HASH MISMATCH: expected {manifest['sha256']}, got {current_hash}"

    expected_sig = sign_manifest(filename, manifest["sha256"])
    if not hmac.compare_digest(expected_sig, manifest["hmac"]):
        return False, "HMAC SIGNATURE INVALID: manifest itself may have been forged"

    return True, "Integrity verified"


# ---------------------------------------------------------------------------
# Ingestion pipeline
# ---------------------------------------------------------------------------
def register_upload(filepath: str):
    """Step 1 (run at 'clinic side'): compute hash, sign manifest, register in DB as trusted baseline."""
    filename = os.path.basename(filepath)
    file_hash = sha256_file(filepath)
    signature = sign_manifest(filename, file_hash)
    write_manifest(filename, file_hash, signature)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO file_integrity (filename, sha256_hash, hmac_signature, registered_at, status) "
        "VALUES (?,?,?,?,?)",
        (filename, file_hash, signature, datetime.now(timezone.utc).isoformat(), "registered"),
    )
    conn.commit()
    conn.close()
    return file_hash, signature


def ingest_file(filepath: str, username: str, password: str):
    """
    Full secure ingestion:
      1. Authenticate + authorize the uploader
      2. Verify file integrity against signed manifest (reject if tampered)
      3. Encrypt each record and store in DB
      4. Log every step
    """
    filename = os.path.basename(filepath)

    # 1. AuthN/AuthZ
    try:
        user = authenticate(username, password)
        require_permission(user, "upload")
    except AuthError as e:
        log_event(username, "UPLOAD_ATTEMPT", filename, "REJECTED_AUTH", str(e))
        return {"status": "rejected", "reason": str(e)}

    # 2. Integrity check
    ok, detail = verify_against_manifest(filepath)
    if not ok:
        # Quarantine the tampered file instead of ingesting it
        quarantine_path = os.path.join(QUARANTINE_DIR, filename)
        os.rename(filepath, quarantine_path) if os.path.exists(filepath) else None
        log_event(user["username"], "UPLOAD_ATTEMPT", filename, "REJECTED_TAMPER", detail)
        return {"status": "rejected", "reason": detail}

    # 3. Encrypt + store
    fernet = get_fernet()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    count = 0
    with open(filepath, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            record_json = json.dumps(row).encode()
            record_hash = hashlib.sha256(record_json).hexdigest()
            encrypted_blob = fernet.encrypt(record_json)
            try:
                cur.execute(
                    "INSERT INTO patients (record_id, clinic_id, encrypted_blob, record_hash, "
                    "source_file, ingested_at) VALUES (?,?,?,?,?,?)",
                    (row["record_id"], row["clinic_id"], encrypted_blob, record_hash,
                     filename, datetime.now(timezone.utc).isoformat()),
                )
                count += 1
            except sqlite3.IntegrityError:
                pass  # duplicate record_id - skip
    conn.commit()
    conn.close()

    log_event(user["username"], "UPLOAD_ATTEMPT", filename, "SUCCESS",
               f"{count} records encrypted and stored")
    return {"status": "success", "records_ingested": count}


def decrypt_record(record_id: str, username: str, password: str):
    """Decrypt a single record - requires 'decrypt' permission (admin only)."""
    user = authenticate(username, password)
    require_permission(user, "decrypt")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT encrypted_blob, record_hash FROM patients WHERE record_id=?", (record_id,))
    row = cur.fetchone()
    conn.close()
    if row is None:
        return None

    blob, stored_hash = row
    fernet = get_fernet()
    plaintext = fernet.decrypt(blob)
    if hashlib.sha256(plaintext).hexdigest() != stored_hash:
        raise ValueError("Record integrity check failed - stored data may be corrupted")

    log_event(user["username"], "DECRYPT_RECORD", record_id, "SUCCESS", "")
    return json.loads(plaintext)
