"""
auth.py
Authentication + Role-Based Access Control (RBAC) for the ingestion system.

Roles:
  - admin: full access (upload, view, manage users, view logs)
  - clinic_uploader: can only upload files for their own clinic
  - auditor: read-only access to logs and integrity records, no patient data decryption
"""
import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "storage", "hospital.db")

PERMISSIONS = {
    "admin": {"upload", "view_patients", "view_logs", "manage_users", "decrypt"},
    "clinic_uploader": {"upload"},
    "auditor": {"view_logs"},
}


class AuthError(Exception):
    pass


def authenticate(username: str, password: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password_hash, salt, role FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    if row is None:
        raise AuthError("Unknown user")

    stored_hash, salt, role = row
    attempt_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), 200_000
    ).hex()

    if attempt_hash != stored_hash:
        raise AuthError("Invalid credentials")

    return {"username": username, "role": role}


def authorize(user: dict, action: str) -> bool:
    return action in PERMISSIONS.get(user["role"], set())


def require_permission(user: dict, action: str):
    if not authorize(user, action):
        raise AuthError(f"User '{user['username']}' (role={user['role']}) "
                         f"is not authorized to perform '{action}'")
