# app/models.py

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ─── Patient ─────────────────────────────────────────────────────────────────

class Patient(Base):
    __tablename__ = "patients"

    id                    = Column(Integer, primary_key=True, index=True)
    name                  = Column(String, nullable=False)
    dob                   = Column(String, nullable=False)   # stored as YYYY-MM-DD
    medical_record_number = Column(String, unique=True, nullable=False)
    created_at            = Column(DateTime, default=_now)

    access_logs = relationship("AccessLog", back_populates="patient")


# ─── AccessLog ────────────────────────────────────────────────────────────────

class AccessLog(Base):
    __tablename__ = "access_logs"

    id         = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False)
    user       = Column(String, nullable=False)
    action     = Column(String, nullable=False)   # VIEW | EDIT | DELETE | PRINT | EXPORT
    timestamp  = Column(DateTime, default=_now)
    ip_address = Column(String, nullable=True)

    patient = relationship("Patient", back_populates="access_logs")


# ─── SecurityAlert ────────────────────────────────────────────────────────────

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id          = Column(Integer, primary_key=True, index=True)
    alert_type  = Column(String, nullable=False)
    severity    = Column(String, nullable=False)   # LOW | MEDIUM | HIGH | CRITICAL
    description = Column(Text, nullable=True)
    created_at  = Column(DateTime, default=_now)

    incident_report = relationship("IncidentReport", back_populates="alert", uselist=False)


# ─── IncidentReport ───────────────────────────────────────────────────────────

class IncidentReport(Base):
    __tablename__ = "incident_reports"

    id         = Column(Integer, primary_key=True, index=True)
    alert_id   = Column(Integer, ForeignKey("security_alerts.id"), nullable=False)
    summary    = Column(Text, nullable=False)
    status     = Column(String, default="OPEN")   # OPEN | IN_REVIEW | CLOSED
    created_at = Column(DateTime, default=_now)

    alert = relationship("SecurityAlert", back_populates="incident_report")


# ─── AppAuditLog ─────────────────────────────────────────────────────────────
# Tracks every authenticated action taken inside this app (HIPAA requirement).

class AppAuditLog(Base):
    __tablename__ = "app_audit_logs"

    id         = Column(Integer, primary_key=True, index=True)
    username   = Column(String, nullable=False)
    role       = Column(String, nullable=True)
    method     = Column(String, nullable=False)   # GET | POST
    path       = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    timestamp  = Column(DateTime, default=_now)


# ─── User ─────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role            = Column(String, default="ANALYST")  # ADMIN | ANALYST | READ_ONLY
    active          = Column(Boolean, default=True)
    created_at      = Column(DateTime, default=_now)
    last_login      = Column(DateTime, nullable=True)


# ─── Setting ──────────────────────────────────────────────────────────────────
# Key-value store for configurable detection thresholds and feature flags.

class Setting(Base):
    __tablename__ = "settings"

    key        = Column(String, primary_key=True)
    value      = Column(String, nullable=False)
    label      = Column(String, nullable=True)
    updated_at = Column(DateTime, default=_now)
