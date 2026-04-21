# app/seed_data.py
# Populates the database with realistic hospital cybersecurity demo data.
# Run this once to fill the DB before launching the dashboard.

from datetime import datetime, timedelta
import random

from app.database import SessionLocal, engine
from app import models


# ─── Demo Data ───────────────────────────────────────────────────────────────

PATIENTS = [
    {"name": "Margaret Holloway",  "dob": "1948-03-12", "medical_record_number": "MRN-1001"},
    {"name": "James Whitfield",     "dob": "1962-07-29", "medical_record_number": "MRN-1002"},
    {"name": "Priya Nair",          "dob": "1985-11-04", "medical_record_number": "MRN-1003"},
    {"name": "Carlos Mendez",       "dob": "1974-06-18", "medical_record_number": "MRN-1004"},
    {"name": "Linda Okafor",        "dob": "1990-01-23", "medical_record_number": "MRN-1005"},
    {"name": "Thomas Bergmann",     "dob": "1955-09-07", "medical_record_number": "MRN-1006"},
    {"name": "Aisha Kamara",        "dob": "2001-04-30", "medical_record_number": "MRN-1007"},
    {"name": "Robert Chung",        "dob": "1967-12-15", "medical_record_number": "MRN-1008"},
]

# Hospital staff who appear in access logs
STAFF_USERS = [
    "dr.patel", "nurse.kim", "dr.osei", "admin.torres",
    "nurse.jackson", "dr.reeves", "billing.chen", "it.support",
]

# Suspicious / external IPs mixed in with normal internal ones
INTERNAL_IPS = [
    "10.0.1.12", "10.0.1.45", "10.0.2.88",
    "192.168.1.5", "192.168.1.22", "192.168.0.101",
]
SUSPICIOUS_IPS = [
    "45.33.32.156", "185.220.101.47", "103.21.244.0", "91.108.4.0",
]

ACTIONS = ["VIEW", "EDIT", "PRINT", "DOWNLOAD", "DELETE"]

ALERT_SCENARIOS = [
    {
        "alert_type": "BRUTE_FORCE",
        "severity":   "HIGH",
        "description": (
            "Multiple failed login attempts detected for user admin.torres. "
            "14 failures in 3 minutes from IP 45.33.32.156."
        ),
    },
    {
        "alert_type": "UNAUTHORIZED_ACCESS",
        "severity":   "HIGH",
        "description": (
            "billing.chen accessed ICU patient records outside of authorized role. "
            "Billing staff should not have access to clinical notes."
        ),
    },
    {
        "alert_type": "ANOMALOUS_DOWNLOAD",
        "severity":   "MEDIUM",
        "description": (
            "nurse.kim downloaded 47 patient records in under 10 minutes. "
            "Volume exceeds normal workflow thresholds."
        ),
    },
    {
        "alert_type": "OFF_HOURS_ACCESS",
        "severity":   "MEDIUM",
        "description": (
            "dr.reeves accessed patient records at 03:14 AM on a non-scheduled shift day. "
            "Access originated from external IP 185.220.101.47."
        ),
    },
    {
        "alert_type": "PRIVILEGE_ESCALATION",
        "severity":   "CRITICAL",
        "description": (
            "it.support account granted itself admin-level database permissions. "
            "Change was not logged through the standard change-control process."
        ),
    },
    {
        "alert_type": "SUSPICIOUS_IP",
        "severity":   "HIGH",
        "description": (
            "Login from IP 103.21.244.0 flagged by threat intelligence feed. "
            "IP is associated with known ransomware distribution network."
        ),
    },
    {
        "alert_type": "DATA_EXFILTRATION",
        "severity":   "CRITICAL",
        "description": (
            "Outbound transfer of 2.3 GB to external host detected from workstation W-114. "
            "Destination IP not on approved transfer whitelist."
        ),
    },
    {
        "alert_type": "REPEATED_RECORD_VIEW",
        "severity":   "LOW",
        "description": (
            "admin.torres viewed the same patient record (MRN-1004) 12 times in one hour. "
            "Flagged for potential unauthorized interest in VIP patient data."
        ),
    },
]

INCIDENT_SUMMARIES = [
    "Investigated brute-force source IP. Blocked at perimeter firewall. "
    "Staff password reset enforced. No evidence of successful login.",

    "Billing user access reviewed. Role permissions corrected in EHR system. "
    "Manager notified. Compliance team flagged for HIPAA review.",

    "Bulk download investigated — nurse confirmed data pull was for shift handoff report. "
    "Workflow process updated to use approved reporting tool instead.",

    "Off-hours access confirmed as unauthorized. Account suspended pending HR review. "
    "External IP traced to personal VPN. Investigation ongoing.",

    "Privilege escalation traced to misconfigured deployment script. "
    "Script corrected and permissions reverted. Patch applied.",
]

INCIDENT_STATUSES = ["OPEN", "IN_REVIEW", "CLOSED"]


# ─── Helper ──────────────────────────────────────────────────────────────────

def random_timestamp(days_back: int = 30) -> datetime:
    """Returns a random datetime within the last N days."""
    offset = random.randint(0, days_back * 24 * 60)  # offset in minutes
    return datetime.utcnow() - timedelta(minutes=offset)


# ─── Seed Function ───────────────────────────────────────────────────────────

def seed_database():
    """
    Drops all existing rows and re-seeds the database with demo data.
    Safe to run multiple times — clears old data first to avoid duplicates.
    """

    # Create tables if they don't exist yet
    models.Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        # ── Clear existing data (order matters due to foreign keys) ──────────
        db.query(models.IncidentReport).delete()
        db.query(models.SecurityAlert).delete()
        db.query(models.AccessLog).delete()
        db.query(models.Patient).delete()
        db.commit()
        print("✓ Cleared existing data")

        # ── Insert Patients ──────────────────────────────────────────────────
        patient_records = []
        for p in PATIENTS:
            patient = models.Patient(**p)
            db.add(patient)
            patient_records.append(patient)

        db.commit()
        # Refresh to get auto-assigned IDs
        for p in patient_records:
            db.refresh(p)
        print(f"✓ Inserted {len(patient_records)} patients")

        # ── Insert Access Logs ───────────────────────────────────────────────
        # 60 realistic log entries spread across patients and staff
        log_count = 0
        for _ in range(60):
            # Occasionally use a suspicious external IP to simulate threats
            use_suspicious = random.random() < 0.15  # 15% chance
            ip = (
                random.choice(SUSPICIOUS_IPS)
                if use_suspicious
                else random.choice(INTERNAL_IPS)
            )

            log = models.AccessLog(
                patient_id = random.choice(patient_records).id,
                user       = random.choice(STAFF_USERS),
                action     = random.choice(ACTIONS),
                timestamp  = random_timestamp(days_back=14),
                ip_address = ip,
            )
            db.add(log)
            log_count += 1

        db.commit()
        print(f"✓ Inserted {log_count} access log entries")

        # ── Insert Security Alerts ───────────────────────────────────────────
        alert_records = []
        for scenario in ALERT_SCENARIOS:
            alert = models.SecurityAlert(
                alert_type  = scenario["alert_type"],
                severity    = scenario["severity"],
                description = scenario["description"],
                created_at  = random_timestamp(days_back=10),
            )
            db.add(alert)
            alert_records.append(alert)

        db.commit()
        for a in alert_records:
            db.refresh(a)
        print(f"✓ Inserted {len(alert_records)} security alerts")

        # ── Insert Incident Reports ──────────────────────────────────────────
        # Link the first 5 alerts to incident reports
        incident_count = 0
        for i, summary in enumerate(INCIDENT_SUMMARIES):
            incident = models.IncidentReport(
                alert_id   = alert_records[i].id,
                summary    = summary,
                status     = random.choice(INCIDENT_STATUSES),
                created_at = random_timestamp(days_back=7),
            )
            db.add(incident)
            incident_count += 1

        db.commit()
        print(f"✓ Inserted {incident_count} incident reports")

        print("")
        print("✅ Database seeded successfully. Launch the server and visit /dashboard.")

    except Exception as e:
        db.rollback()
        print(f"❌ Seeding failed: {e}")
        raise

    finally:
        db.close()


# ─── Entry Point ─────────────────────────────────────────────────────────────
# Allows running this file directly: python -m app.seed_data

if __name__ == "__main__":
    seed_database()