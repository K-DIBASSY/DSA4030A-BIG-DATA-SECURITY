import os
import glob
from secure_ingest import register_upload, ingest_file

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
INCOMING_DIR = os.path.join(BASE_DIR, "data", "incoming")

if __name__ == "__main__":
    files = sorted(glob.glob(os.path.join(INCOMING_DIR, "*.csv")))
    print(f"Found {len(files)} incoming batch files\n")

    for filepath in files:
        filename = os.path.basename(filepath)
        # Clinic side: register (hash + sign) the file before "sending" it
        file_hash, sig = register_upload(filepath)
        print(f"[REGISTERED] {filename}\n  sha256={file_hash}\n  hmac={sig}")

        # Hospital side: uploader logs in and ingests
        clinic_user = "clinic_nairobi_a"  # demo: same uploader account for simplicity
        result = ingest_file(filepath, clinic_user, "ClinicUpload!99")
        print(f"  -> {result}\n")
