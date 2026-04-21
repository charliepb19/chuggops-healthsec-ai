# app/main.py

import asyncio
import os
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Form, Request, Depends, UploadFile, File
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy import text
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.database import engine, get_db, SessionLocal
from app import models
from app.auth import verify as verify_credentials, seed_admin, hash_password
from app.detection import save_detected_alerts
from app.ai_engine import analyse_alert_from_model
from app.ingestion import ingest_csv
from app.security import (
    is_locked_out, record_failure, clear_failures, validate_password,
    LOCKOUT_ATTEMPTS, LOCKOUT_MINUTES, _failures,
)

INACTIVITY_MINUTES = 30
PER_PAGE           = 25

# Default detection settings seeded into the DB on first startup
_DEFAULT_SETTINGS = [
    ("failed_access_limit",     "3",                           "Repeated Delete Limit"),
    ("failed_access_window_min","60",                          "Repeated Delete Window (min)"),
    ("off_hours_start",         "22",                          "Off-Hours Start (24-h clock)"),
    ("off_hours_end",           "6",                           "Off-Hours End (24-h clock)"),
    ("high_volume_limit",       "10",                          "High-Volume Threshold"),
    ("high_volume_window_min",  "60",                          "High-Volume Window (min)"),
    ("suspicious_ip_prefixes",  "45.33,185.220,103.21,91.108", "Suspicious IP Prefixes (comma-separated)"),
    ("ml_detection_enabled",    "true",                        "ML Anomaly Detection Enabled"),
    ("ml_contamination",        "0.05",                        "ML Contamination Rate (0.01–0.20)"),
]


def seed_default_settings(db):
    for key, value, label in _DEFAULT_SETTINGS:
        if not db.query(models.Setting).filter(models.Setting.key == key).first():
            db.add(models.Setting(key=key, value=value, label=label))
    db.commit()


# ─── Startup / Shutdown ───────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    models.Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_admin(db)
        seed_default_settings(db)
    finally:
        db.close()
    from app.scheduler import start as start_scheduler
    start_scheduler()
    yield
    from app.scheduler import stop as stop_scheduler
    stop_scheduler()


# ─── App Init ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ChuggOps HealthSec AI",
    description="Healthcare cybersecurity monitoring platform",
    version="0.2.0",
    lifespan=lifespan,
)


# ─── Middleware ───────────────────────────────────────────────────────────────
# Execution order for requests: SessionMiddleware → AuthMiddleware → AuditMiddleware → Route
# add_middleware() inserts at position 0, so last added = outermost = runs first.

class AuditMiddleware(BaseHTTPMiddleware):
    """Logs every authenticated request to the AppAuditLog table."""
    SKIP = {"/favicon.ico"}

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.startswith("/static") or path in self.SKIP:
            return response
        user = request.session.get("user")
        if not user:
            return response
        db = SessionLocal()
        try:
            db.add(models.AppAuditLog(
                username   = user,
                role       = request.session.get("role"),
                method     = request.method,
                path       = path,
                ip_address = request.client.host if request.client else None,
            ))
            db.commit()
        except Exception:
            pass
        finally:
            db.close()
        return response


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/static") or path in ("/login", "/health"):
            return await call_next(request)
        if not request.session.get("user"):
            return RedirectResponse("/login", status_code=302)

        last_active = request.session.get("last_active")
        if last_active:
            elapsed = (
                datetime.now(timezone.utc)
                - datetime.fromisoformat(last_active).replace(tzinfo=timezone.utc)
            )
            if elapsed > timedelta(minutes=INACTIVITY_MINUTES):
                request.session.clear()
                return RedirectResponse("/login?reason=timeout", status_code=302)

        request.session["last_active"] = datetime.now(timezone.utc).isoformat()
        return await call_next(request)


# Innermost first; SessionMiddleware added last so it wraps everything
app.add_middleware(AuditMiddleware)
app.add_middleware(AuthMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key    = os.getenv("SESSION_SECRET", "chuggops-dev-key-change-in-production"),
    session_cookie= "chuggops_session",
    same_site     = "strict",
    https_only    = False,
    max_age       = 8 * 60 * 60,
)


# ─── Static Files & Templates ─────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def _open_alert_count() -> int:
    db = SessionLocal()
    try:
        return (
            db.query(models.SecurityAlert)
            .outerjoin(models.IncidentReport)
            .filter(models.IncidentReport.id == None)  # noqa: E711
            .count()
        )
    finally:
        db.close()


def _open_incident_count() -> int:
    db = SessionLocal()
    try:
        return db.query(models.IncidentReport).filter(
            models.IncidentReport.status == "OPEN"
        ).count()
    finally:
        db.close()


templates.env.globals["open_alert_count"]    = _open_alert_count
templates.env.globals["open_incident_count"] = _open_incident_count


# ─── Pagination helper ────────────────────────────────────────────────────────

def paginate(query, page: int, per_page: int = PER_PAGE) -> dict:
    total       = query.count()
    total_pages = max(1, (total + per_page - 1) // per_page)
    page        = max(1, min(page, total_pages))
    items       = query.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "items":       items,
        "page":        page,
        "per_page":    per_page,
        "total":       total,
        "total_pages": total_pages,
        "has_prev":    page > 1,
        "has_next":    page < total_pages,
    }


# ─── Helpers ─────────────────────────────────────────────────────────────────

def is_admin(request: Request) -> bool:
    return request.session.get("role") == "ADMIN"


# ─── Auth Routes ──────────────────────────────────────────────────────────────

@app.get("/login")
def login_page(request: Request, error: str = None, reason: str = None):
    ctx = {"title": "Sign In"}
    if error:
        ctx["error"] = "Invalid username or password."
    if reason == "timeout":
        ctx["error"] = "Your session expired due to inactivity. Please sign in again."
    return templates.TemplateResponse(request, "login.html", ctx)


@app.post("/login")
async def login_post(
    request:  Request,
    username: str     = Form(...),
    password: str     = Form(...),
    db:       Session = Depends(get_db),
):
    locked, minutes = is_locked_out(username)
    if locked:
        return templates.TemplateResponse(request, "login.html", {
            "title": "Sign In",
            "error": f"Account locked — too many failed attempts. Try again in {minutes} minute(s).",
        })

    user = verify_credentials(username, password, db)
    if user:
        clear_failures(username)
        request.session["user"]        = user.username
        request.session["role"]        = user.role
        user.last_login                = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()
        return RedirectResponse("/dashboard", status_code=303)

    record_failure(username)
    attempts_so_far = len(_failures.get(username, []))
    left = LOCKOUT_ATTEMPTS - attempts_so_far
    msg = (
        f"Account locked for {LOCKOUT_MINUTES} minutes."
        if left <= 0
        else f"Invalid username or password. {left} attempt(s) remaining before lockout."
    )
    return templates.TemplateResponse(request, "login.html", {"title": "Sign In", "error": msg})


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ─── Core Pages ───────────────────────────────────────────────────────────────

@app.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"title": "ChuggOps HealthSec AI"})


@app.post("/run-detection")
def run_detection(db: Session = Depends(get_db)):
    count = save_detected_alerts(db)
    return RedirectResponse(url=f"/dashboard?detected={count}", status_code=303)


@app.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db), detected: int = None):
    ctx = {
        "title":          "Dashboard",
        "patient_count":  db.query(models.Patient).count(),
        "log_count":      db.query(models.AccessLog).count(),
        "alert_count":    db.query(models.SecurityAlert).count(),
        "incident_count": db.query(models.IncidentReport).count(),
        "recent_logs":    db.query(models.AccessLog).order_by(
                              models.AccessLog.timestamp.desc()).limit(5).all(),
        "recent_alerts":  db.query(models.SecurityAlert).order_by(
                              models.SecurityAlert.created_at.desc()).limit(5).all(),
    }
    if detected is not None:
        ctx["detected"] = detected
    return templates.TemplateResponse(request, "dashboard.html", ctx)


# ─── Patients ─────────────────────────────────────────────────────────────────

@app.get("/patients")
def patients(request: Request, db: Session = Depends(get_db),
             q: str = None, page: int = 1):
    query = db.query(models.Patient).order_by(models.Patient.name)
    if q:
        query = query.filter(
            models.Patient.name.ilike(f"%{q}%") |
            models.Patient.medical_record_number.ilike(f"%{q}%")
        )
    p = paginate(query, page)
    return templates.TemplateResponse(request, "patients.html", {
        "title":      "Patients",
        "patients":   p["items"],
        "pagination": p,
        "q":          q or "",
    })


@app.get("/patients/{patient_id}")
def patient_detail(request: Request, patient_id: int,
                   db: Session = Depends(get_db), page: int = 1):
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if patient is None:
        return RedirectResponse("/patients", status_code=303)
    query = (
        db.query(models.AccessLog)
        .filter(models.AccessLog.patient_id == patient_id)
        .order_by(models.AccessLog.timestamp.desc())
    )
    p = paginate(query, page)
    return templates.TemplateResponse(request, "patient_detail.html", {
        "title":      patient.name,
        "patient":    patient,
        "logs":       p["items"],
        "pagination": p,
    })


# ─── Alerts ───────────────────────────────────────────────────────────────────

@app.get("/alerts")
def alerts(request: Request, db: Session = Depends(get_db),
           severity: str = None, page: int = 1):
    query = db.query(models.SecurityAlert).order_by(models.SecurityAlert.created_at.desc())
    if severity:
        query = query.filter(models.SecurityAlert.severity == severity.upper())
    p = paginate(query, page)
    return templates.TemplateResponse(request, "alerts.html", {
        "title":      "Security Alerts",
        "alerts":     p["items"],
        "pagination": p,
        "severity":   severity or "",
    })


@app.get("/alerts/{alert_id}")
def alert_detail(request: Request, alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(models.SecurityAlert).filter(
        models.SecurityAlert.id == alert_id).first()
    if alert is None:
        return RedirectResponse("/alerts", status_code=303)
    return templates.TemplateResponse(request, "alert_detail.html", {
        "title":    f"Alert #{alert_id}",
        "alert":    alert,
        "analysis": analyse_alert_from_model(alert),
    })


@app.post("/alerts/{alert_id}/raise-incident")
def raise_incident(alert_id: int, summary: str = Form(...), db: Session = Depends(get_db)):
    alert = db.query(models.SecurityAlert).filter(
        models.SecurityAlert.id == alert_id).first()
    if alert is None or alert.incident_report is not None:
        return RedirectResponse(f"/alerts/{alert_id}", status_code=303)
    inc = models.IncidentReport(alert_id=alert_id, summary=summary.strip(), status="OPEN")
    db.add(inc)
    db.commit()
    db.refresh(inc)
    return RedirectResponse(f"/incidents/{inc.id}", status_code=303)


# ─── Incidents ────────────────────────────────────────────────────────────────

@app.get("/incidents")
def incidents(request: Request, db: Session = Depends(get_db),
              status: str = None, page: int = 1):
    query = db.query(models.IncidentReport).order_by(models.IncidentReport.created_at.desc())
    if status:
        query = query.filter(models.IncidentReport.status == status.upper())
    p = paginate(query, page)
    return templates.TemplateResponse(request, "incident.html", {
        "title":      "Incident Reports",
        "incidents":  p["items"],
        "pagination": p,
        "status_filter": status or "",
    })


@app.get("/incidents/{incident_id}")
def incident_detail(request: Request, incident_id: int,
                    db: Session = Depends(get_db), updated: int = None):
    inc = db.query(models.IncidentReport).filter(
        models.IncidentReport.id == incident_id).first()
    if inc is None:
        return RedirectResponse("/incidents", status_code=303)
    ctx = {"title": f"INC-{incident_id:04d}", "incident": inc}
    if updated:
        ctx["updated"] = True
    return templates.TemplateResponse(request, "incident_detail.html", ctx)


@app.post("/incidents/{incident_id}/update")
def update_incident(incident_id: int, status: str = Form(...),
                    summary: str = Form(...), db: Session = Depends(get_db)):
    inc = db.query(models.IncidentReport).filter(
        models.IncidentReport.id == incident_id).first()
    if inc and status in ("OPEN", "IN_REVIEW", "CLOSED"):
        inc.status  = status
        inc.summary = summary.strip()
        db.commit()
    return RedirectResponse(f"/incidents/{incident_id}?updated=1", status_code=303)


# ─── Data Ingestion ───────────────────────────────────────────────────────────

@app.get("/ingest")
def ingest_page(request: Request):
    ctx = {"title": "Import Data"}
    raw = request.session.pop("ingest_result", None)
    if raw:
        ctx["result"] = json.loads(raw)
    return templates.TemplateResponse(request, "ingest.html", ctx)


@app.post("/ingest")
async def ingest_upload(request: Request, file: UploadFile = File(...),
                        db: Session = Depends(get_db)):
    content = (await file.read()).decode("utf-8-sig", errors="replace")
    result  = ingest_csv(db, content)
    request.session["ingest_result"] = json.dumps(result)
    return RedirectResponse("/ingest", status_code=303)


# ─── Audit Log (admin only) ───────────────────────────────────────────────────

@app.get("/audit-log")
def audit_log(request: Request, db: Session = Depends(get_db),
              user_filter: str = None, page: int = 1):
    if not is_admin(request):
        return RedirectResponse("/dashboard", status_code=303)
    query = db.query(models.AppAuditLog).order_by(models.AppAuditLog.timestamp.desc())
    if user_filter:
        query = query.filter(models.AppAuditLog.username == user_filter)
    p = paginate(query, page)
    users = [r[0] for r in db.query(models.AppAuditLog.username).distinct().all()]
    return templates.TemplateResponse(request, "audit_log.html", {
        "title":       "Audit Log",
        "logs":        p["items"],
        "pagination":  p,
        "user_filter": user_filter or "",
        "users":       sorted(users),
    })


# ─── User Management (admin only) ────────────────────────────────────────────

@app.get("/users")
def users_page(request: Request, db: Session = Depends(get_db),
               added: int = None, error: str = None):
    if not is_admin(request):
        return RedirectResponse("/dashboard", status_code=303)
    all_users = db.query(models.User).order_by(models.User.created_at).all()
    ctx = {"title": "Users", "users": all_users}
    if added:
        ctx["added"] = True
    if error:
        ctx["error"] = error
    return templates.TemplateResponse(request, "users.html", ctx)


@app.post("/users/add")
def add_user(request: Request, username: str = Form(...),
             password: str = Form(...), role: str = Form(...),
             db: Session = Depends(get_db)):
    if not is_admin(request):
        return RedirectResponse("/dashboard", status_code=303)
    if role not in ("ADMIN", "ANALYST", "READ_ONLY"):
        return RedirectResponse("/users?error=Invalid+role", status_code=303)
    pw_errors = validate_password(password)
    if pw_errors:
        return RedirectResponse(f"/users?error={pw_errors[0].replace(' ', '+')}", status_code=303)
    if db.query(models.User).filter(models.User.username == username).first():
        return RedirectResponse("/users?error=Username+already+exists", status_code=303)
    db.add(models.User(
        username        = username.strip(),
        hashed_password = hash_password(password),
        role            = role,
        active          = True,
    ))
    db.commit()
    return RedirectResponse("/users?added=1", status_code=303)


@app.post("/users/{user_id}/toggle")
def toggle_user(request: Request, user_id: int, db: Session = Depends(get_db)):
    if not is_admin(request):
        return RedirectResponse("/dashboard", status_code=303)
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        user.active = not user.active
        db.commit()
    return RedirectResponse("/users", status_code=303)


# ─── Health Check ────────────────────────────────────────────────────────────

@app.get("/health")
def health(db: Session = Depends(get_db)):
    """
    Used by Docker HEALTHCHECK, load balancers, and container orchestrators.
    Returns 200 when the app and database are both reachable.
    """
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    from app.scheduler import scheduler
    status = "ok" if db_ok else "degraded"
    return JSONResponse(
        status_code = 200 if db_ok else 503,
        content = {
            "status":    status,
            "database":  "ok" if db_ok else "error",
            "scheduler": "running" if scheduler.running else "stopped",
        },
    )


# ─── Server-Sent Events ───────────────────────────────────────────────────────

@app.get("/events")
async def sse_events(request: Request):
    """
    Streams live dashboard counts to the browser every 15 seconds.
    Payload: {"alerts": int, "incidents": int, "open_incidents": int}
    """
    async def stream():
        while True:
            if await request.is_disconnected():
                break
            db = SessionLocal()
            try:
                alerts       = db.query(models.SecurityAlert).count()
                incidents    = db.query(models.IncidentReport).count()
                open_inc     = db.query(models.IncidentReport).filter(
                                   models.IncidentReport.status == "OPEN").count()
                open_alerts  = (
                    db.query(models.SecurityAlert)
                    .outerjoin(models.IncidentReport)
                    .filter(models.IncidentReport.id == None)  # noqa: E711
                    .count()
                )
            finally:
                db.close()
            payload = json.dumps({
                "alerts":       alerts,
                "incidents":    incidents,
                "open_incidents": open_inc,
                "open_alerts":  open_alerts,
            })
            yield f"data: {payload}\n\n"
            await asyncio.sleep(15)

    return StreamingResponse(
        stream(),
        media_type = "text/event-stream",
        headers    = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── Detection Settings (admin only) ─────────────────────────────────────────

@app.get("/settings")
def settings_page(request: Request, db: Session = Depends(get_db),
                  saved: int = None):
    if not is_admin(request):
        return RedirectResponse("/dashboard", status_code=303)
    rows     = db.query(models.Setting).order_by(models.Setting.key).all()
    settings = {r.key: r for r in rows}

    from app.ml_detection import status as ml_status
    ctx = {
        "title":    "Detection Settings",
        "settings": settings,
        "ml":       ml_status(),
    }
    if saved:
        ctx["saved"] = True
    return templates.TemplateResponse(request, "settings.html", ctx)


@app.post("/settings/save")
async def settings_save_form(request: Request, db: Session = Depends(get_db)):
    if not is_admin(request):
        return RedirectResponse("/dashboard", status_code=303)
    form    = await request.form()
    allowed = {k for k, _, _ in _DEFAULT_SETTINGS}
    now     = datetime.now(timezone.utc).replace(tzinfo=None)
    for key in allowed:
        val = form.get(key)
        if val is None:
            continue
        row = db.query(models.Setting).filter(models.Setting.key == key).first()
        if row:
            row.value      = str(val).strip()
            row.updated_at = now
    db.commit()
    return RedirectResponse("/settings?saved=1", status_code=303)


@app.post("/settings/retrain")
def settings_retrain(request: Request, db: Session = Depends(get_db)):
    if not is_admin(request):
        return RedirectResponse("/dashboard", status_code=303)
    from app.ml_detection import train
    train(db)
    return RedirectResponse("/settings?saved=1", status_code=303)
