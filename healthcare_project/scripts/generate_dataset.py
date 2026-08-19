"""
generate_dataset.py
Generates synthetic patient records simulating hourly uploads from multiple clinics.
No real patient data is used - all records are synthetically generated for testing.

Output: one CSV per simulated clinic batch, each ~100,000+ records total across batches.
"""
import csv
import random
import uuid
from datetime import datetime, timedelta
import os

random.seed(42)

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "incoming")
os.makedirs(OUTPUT_DIR, exist_ok=True)

CLINICS = ["Clinic_Nairobi_A", "Clinic_Nairobi_B", "Clinic_Mombasa_A",
           "Clinic_Kisumu_A", "Clinic_Nakuru_A"]

FIRST_NAMES = ["John", "Mary", "Peter", "Grace", "James", "Jane", "David",
               "Ann", "Samuel", "Faith", "Michael", "Ruth", "Joseph", "Alice",
               "Daniel", "Esther", "Paul", "Lucy", "Kevin", "Diana"]
LAST_NAMES = ["Mwangi", "Otieno", "Wanjiru", "Kamau", "Achieng", "Kiprop",
              "Njoroge", "Wafula", "Mutua", "Chebet", "Odhiambo", "Kariuki",
              "Nyambura", "Barasa", "Mbugua"]
CONDITIONS = ["Hypertension", "Type 2 Diabetes", "Malaria", "Asthma",
              "Common Cold", "Typhoid", "Tuberculosis", "COVID-19",
              "Arthritis", "Migraine", "Anemia", "Pneumonia"]
DEPARTMENTS = ["Outpatient", "Emergency", "Maternity", "Pediatrics",
               "Surgery", "Cardiology", "General Medicine"]
BLOOD_TYPES = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]


def gen_record(record_id: int, clinic: str, timestamp: datetime) -> dict:
    dob = datetime(1940, 1, 1) + timedelta(days=random.randint(0, 30000))
    return {
        "record_id": str(uuid.uuid4()),
        "patient_ref": f"P{record_id:08d}",
        "clinic_id": clinic,
        "first_name": random.choice(FIRST_NAMES),
        "last_name": random.choice(LAST_NAMES),
        "dob": dob.strftime("%Y-%m-%d"),
        "gender": random.choice(["M", "F"]),
        "blood_type": random.choice(BLOOD_TYPES),
        "department": random.choice(DEPARTMENTS),
        "diagnosis": random.choice(CONDITIONS),
        "systolic_bp": random.randint(90, 160),
        "diastolic_bp": random.randint(60, 100),
        "heart_rate": random.randint(55, 110),
        "temperature_c": round(random.uniform(36.0, 39.5), 1),
        "visit_timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "attending_physician": f"Dr. {random.choice(LAST_NAMES)}",
        "notes": "Routine visit - synthetic record for security testing.",
    }


def generate_hourly_batches(total_records: int = 120_000, batches: int = 12):
    """Simulate clinics uploading batches hourly."""
    per_batch = total_records // batches
    record_counter = 1
    start_time = datetime(2026, 7, 18, 0, 0, 0)

    manifest = []
    for b in range(batches):
        clinic = CLINICS[b % len(CLINICS)]
        batch_time = start_time + timedelta(hours=b)
        filename = f"{clinic}_{batch_time.strftime('%Y%m%d_%H%M')}.csv"
        filepath = os.path.join(OUTPUT_DIR, filename)

        with open(filepath, "w", newline="") as f:
            fieldnames = list(gen_record(1, clinic, batch_time).keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for _ in range(per_batch):
                writer.writerow(gen_record(record_counter, clinic, batch_time))
                record_counter += 1

        manifest.append({"file": filename, "clinic": clinic, "records": per_batch})
        print(f"Generated {filename} ({per_batch} records)")

    print(f"\nTotal records generated: {record_counter - 1}")
    return manifest


if __name__ == "__main__":
    generate_hourly_batches()
