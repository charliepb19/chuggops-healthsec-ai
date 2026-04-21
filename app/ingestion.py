# app/ingestion.py
# Ingests Epic EHR audit log CSV exports into the ChuggOps database.
#
# Expected CSV columns (Epic standard export):
#   Access Date, User Login, User Name, Patient MRN, Patient Name,
#   Date of Birth, Action, Department, IP Address, Reason
#
# Column matching is flexible — minor variations in capitalisation and
# spacing are handled automatically via the COLUMN_MAP aliases below.

import io
import csv
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from app import models

logger = logging.getLogger("ingestion")


# ── Column name aliases ───────────────────────────────────────────────────────
# Maps our internal field names to every known column header variation.

COLUMN_MAP = {
    "timestamp":    ["access date", "access_date", "datetime", "date",
                     "log date", "log_date", "timestamp", "event date"],
    "user":         ["user login", "user_login", "username", "login",
                     "user id", "user_id", "staff login", "staff id", "userid"],
    "patient_mrn":  ["patient mrn", "patient_mrn", "mrn",
                     "medical record", "medical record number",
                     "medical_record_number", "record number"],
    "patient_name": ["patient name", "patient_name", "patient", "name"],
    "patient_dob":  ["date of birth", "date_of_birth", "dob",
                     "birth date", "birthdate", "patient dob"],
    "action":       ["action", "action type", "action_type",
                     "event", "activity", "access type", "access_type"],
    "ip_address":   ["ip address", "ip_address", "ip", "workstation ip",
                     "workstation_ip", "source ip", "source_ip", "workstation"],
}


# ── Action normalisation ──────────────────────────────────────────────────────
# Maps Epic action strings to our simplified internal set.

ACTION_MAP = {
    "chart access":    "VIEW",  "result review":   "VIEW",
    "order review":    "VIEW",  "patient lookup":  "VIEW",
    "summary review":  "VIEW",  "chart view":      "VIEW",
    "view":            "VIEW",  "read":            "VIEW",
    "chart access (hx read)": "VIEW",
    "chart update":    "EDIT",  "order entry":     "EDIT",
    "result entry":    "EDIT",  "chart update (write)": "EDIT",
    "update":          "EDIT",  "edit":            "EDIT",  "modify": "EDIT",
    "chart delete":    "DELETE","order cancel":    "DELETE",
    "delete":          "DELETE","remove":          "DELETE","void": "DELETE",
    "print":           "PRINT", "chart print":     "PRINT",
    "export":          "EXPORT","download":        "EXPORT","report export": "EXPORT",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_headers(headers: list[str]) -> dict[str, str]:
    """
    Returns internal_field → actual_csv_column mapping.
    Raises ValueError listing any missing required columns.
    """
    lowered = {h.strip().lower(): h for h in headers}
    resolved = {}

    for field, aliases in COLUMN_MAP.items():
        for alias in aliases:
            if alias in lowered:
                resolved[field] = lowered[alias]
                break

    missing = [f for f in ("timestamp", "user", "patient_mrn") if f not in resolved]
    if missing:
        raise ValueError(
            f"Missing required columns: {missing}. "
            f"Columns found in file: {list(lowered.keys())}"
        )
    return resolved


def _normalise_action(raw: str) -> str:
    return ACTION_MAP.get(raw.strip().lower(), raw.strip().upper()[:10])


def _parse_dt(raw: str) -> datetime:
    for fmt in (
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
        "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
        "%m/%d/%Y", "%Y-%m-%d",
        "%d/%m/%Y %H:%M:%S", "%d/%m/%Y",
    ):
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognised date format: '{raw}'")


def _get_or_create_patient(
    db: Session, mrn: str, name: str, dob: str
) -> tuple[models.Patient, bool]:
    """Returns (patient, created). Flushes but does not commit."""
    patient = db.query(models.Patient).filter(
        models.Patient.medical_record_number == mrn
    ).first()

    if patient:
        return patient, False

    patient = models.Patient(
        name=name.strip() if name else f"Patient {mrn}",
        dob=dob.strip() if dob else "Unknown",
        medical_record_number=mrn,
    )
    db.add(patient)
    db.flush()
    return patient, True


# ── Public entry point ────────────────────────────────────────────────────────

def ingest_csv(db: Session, content: str) -> dict:
    """
    Parses an Epic audit log CSV string and inserts new AccessLog rows.

    Returns a summary:
        imported         — new log rows added
        skipped          — duplicates or incomplete rows bypassed
        patients_created — new Patient records auto-created
        errors           — up to 10 row-level error messages
    """
    reader = csv.DictReader(io.StringIO(content))

    if not reader.fieldnames:
        return {"imported": 0, "skipped": 0, "patients_created": 0,
                "errors": ["File appears to be empty or has no header row."]}

    try:
        col = _resolve_headers(list(reader.fieldnames))
    except ValueError as e:
        return {"imported": 0, "skipped": 0, "patients_created": 0, "errors": [str(e)]}

    imported         = 0
    skipped          = 0
    patients_created = 0
    errors           = []
    seen             = set()   # deduplicate within this file

    for i, row in enumerate(reader, start=2):
        try:
            raw_ts = row.get(col["timestamp"], "").strip()
            user   = row.get(col["user"],      "").strip()
            mrn    = row.get(col["patient_mrn"], "").strip()

            if not raw_ts or not user or not mrn:
                skipped += 1
                continue

            ts     = _parse_dt(raw_ts)
            action = _normalise_action(row.get(col.get("action", ""), "") or "VIEW")
            ip     = (row.get(col.get("ip_address", ""), "") or "").strip() or None
            name   = row.get(col.get("patient_name", ""), "").strip()
            dob    = row.get(col.get("patient_dob",  ""), "").strip()

            # Skip exact duplicates within the file
            key = (user, mrn, raw_ts, action)
            if key in seen:
                skipped += 1
                continue
            seen.add(key)

            # Skip rows already in the database
            exists = db.query(models.AccessLog).filter(
                models.AccessLog.user      == user,
                models.AccessLog.timestamp == ts,
            ).first()
            if exists:
                skipped += 1
                continue

            patient, created = _get_or_create_patient(db, mrn, name, dob)
            if created:
                patients_created += 1

            db.add(models.AccessLog(
                patient_id = patient.id,
                user       = user,
                action     = action,
                timestamp  = ts,
                ip_address = ip,
            ))
            imported += 1

        except Exception as e:
            if len(errors) < 10:
                errors.append(f"Row {i}: {e}")
            skipped += 1
            continue

    db.commit()
    return {
        "imported":         imported,
        "skipped":          skipped,
        "patients_created": patients_created,
        "errors":           errors,
    }
