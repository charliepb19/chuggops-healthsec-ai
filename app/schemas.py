# app/schemas.py
# Pydantic schemas define the shape of data coming IN and going OUT of the API.
# Each model gets two schemas: a Base (shared fields) and a Response (includes id/timestamps).

from pydantic import BaseModel
from datetime import datetime
from typing import Optional


# ─── Patient ────────────────────────────────────────────────────────────────

class PatientBase(BaseModel):
    name: str
    dob: str                    # expected format: YYYY-MM-DD
    medical_record_number: str


class PatientCreate(PatientBase):
    pass                        # no extra fields needed to create a patient


class PatientResponse(PatientBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True  # allows reading from SQLAlchemy model objects


# ─── AccessLog ───────────────────────────────────────────────────────────────

class AccessLogBase(BaseModel):
    patient_id: int
    user: str
    action: str
    ip_address: Optional[str] = None


class AccessLogCreate(AccessLogBase):
    pass


class AccessLogResponse(AccessLogBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True


# ─── SecurityAlert ───────────────────────────────────────────────────────────

class SecurityAlertBase(BaseModel):
    alert_type: str
    severity: str
    description: Optional[str] = None


class SecurityAlertCreate(SecurityAlertBase):
    pass


class SecurityAlertResponse(SecurityAlertBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# ─── IncidentReport ──────────────────────────────────────────────────────────

class IncidentReportBase(BaseModel):
    alert_id: int
    summary: str
    status: str = "OPEN"


class IncidentReportCreate(IncidentReportBase):
    pass


class IncidentReportResponse(IncidentReportBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True