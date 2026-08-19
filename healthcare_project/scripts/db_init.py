"""
db_init.py
Initializes the SQLite storage schema:
 - patients: encrypted patient data storage
 - upload_log: audit trail of every ingestion attempt (success/failure/tamper)
 - file_integrity: hash registry for uploaded files
 - users: simple auth store for role-based access control (RBAC)
"""
import sqlite3
import os
import hashlib

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "storage", "hospital.db")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','clinic_uploader','auditor'))
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            db_id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id TEXT UNIQUE NOT NULL,
            clinic_id TEXT NOT NULL,
            encrypted_blob BLOB NOT NULL,
            record_hash TEXT NOT NULL,
            source_file TEXT NOT NULL,
            ingested_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS file_integrity (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            hmac_signature TEXT NOT NULL,
            registered_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'verified'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS upload_log (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            filename TEXT,
            status TEXT NOT NULL,
            detail TEXT
        )
    """)

    # Seed demo users for RBAC testing (passwords salted+hashed, never plaintext)
    demo_users = [
        ("hospital_admin", "AdminPass!2026", "admin"),
        ("clinic_nairobi_a", "ClinicUpload!99", "clinic_uploader"),
        ("compliance_auditor", "AuditView!2026", "auditor"),
    ]
    for username, pw, role in demo_users:
        salt = os.urandom(16).hex()
        pw_hash = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()
        cur.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, salt, role) VALUES (?,?,?,?)",
            (username, pw_hash, salt, role),
        )

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")


if __name__ == "__main__":
    init_db()
