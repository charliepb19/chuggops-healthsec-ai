# app/detection.py
# Rule-based suspicious activity detection engine.
# Each function inspects access logs and returns a list of alert dicts
# that can be saved to the SecurityAlert table or displayed on the dashboard.

from datetime import datetime, timedelta, timezone


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
from collections import defaultdict
from sqlalchemy.orm import Session

from app import models


# ─── Thresholds ───────────────────────────────────────────────────────────────
# Centralised defaults — overridden at runtime by values from the settings table.

FAILED_ACCESS_ACTION      = "DELETE"
FAILED_ACCESS_LIMIT       = 3
FAILED_ACCESS_WINDOW_MIN  = 60
OFF_HOURS_START           = 22
OFF_HOURS_END             = 6
HIGH_VOLUME_ACTION        = "VIEW"
HIGH_VOLUME_LIMIT         = 10
HIGH_VOLUME_WINDOW_MIN    = 60
SUSPICIOUS_IP_PREFIXES    = ["45.33", "185.220", "103.21", "91.108"]


def _load_settings(db) -> dict:
    """Read all rows from the settings table into a plain dict."""
    try:
        rows = db.query(models.Setting).all()
        return {r.key: r.value for r in rows}
    except Exception:
        return {}


def _get(cfg: dict, key: str, default):
    """Return cfg[key] cast to the same type as default, or default if missing."""
    val = cfg.get(key)
    if val is None:
        return default
    try:
        return type(default)(val)
    except (ValueError, TypeError):
        return default


# ─── Shared Helpers ──────────────────────────────────────────────────────────

def _logs_within_window(logs: list, window_minutes: int) -> list:
    """Return only logs whose timestamp falls within the last N minutes."""
    cutoff = _utcnow() - timedelta(minutes=window_minutes)
    return [log for log in logs if log.timestamp >= cutoff]


def _is_suspicious_ip(ip: str) -> bool:
    """Return True if the IP starts with any known suspicious prefix."""
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in SUSPICIOUS_IP_PREFIXES)


def _make_alert(alert_type: str, severity: str, description: str) -> dict:
    """Build a standard alert dictionary ready to display or persist."""
    return {
        "alert_type":  alert_type,
        "severity":    severity,
        "description": description,
        "created_at":  _utcnow(),
    }


# ─── Rule 1: Repeated High-Risk Actions ──────────────────────────────────────

def detect_repeated_failed_access(db: Session, cfg: dict = None) -> list:
    """
    Fires when the same user performs too many high-risk actions (DELETE)
    within the look-back window. Simulates repeated failed/suspicious attempts.

    Returns a list of alert dicts — one per offending user.
    """
    cfg    = cfg or {}
    limit  = _get(cfg, "failed_access_limit",      FAILED_ACCESS_LIMIT)
    window = _get(cfg, "failed_access_window_min",  FAILED_ACCESS_WINDOW_MIN)
    alerts = []

    # Fetch all high-risk action logs
    risky_logs = (
        db.query(models.AccessLog)
        .filter(models.AccessLog.action == FAILED_ACCESS_ACTION)
        .all()
    )

    # Only keep logs within the time window
    recent = _logs_within_window(risky_logs, window)

    # Count occurrences per user
    user_counts = defaultdict(list)
    for log in recent:
        user_counts[log.user].append(log)

    for user, user_logs in user_counts.items():
        if len(user_logs) >= limit:
            # Check if any of those logs came from a suspicious IP
            sus_ips = [
                log.ip_address for log in user_logs
                if _is_suspicious_ip(log.ip_address)
            ]
            ip_note = (
                f" Suspicious IPs involved: {', '.join(set(sus_ips))}."
                if sus_ips else ""
            )

            alerts.append(_make_alert(
                alert_type  = "REPEATED_FAILED_ACCESS",
                severity    = "HIGH" if sus_ips else "MEDIUM",
                description = (
                    f"User '{user}' performed {len(user_logs)} DELETE actions "
                    f"within the last {window} minutes."
                    f"{ip_note}"
                ),
            ))

    return alerts


# ─── Rule 2: Off-Hours Access ─────────────────────────────────────────────────

def detect_off_hours_access(db: Session, cfg: dict = None) -> list:
    """
    Fires when any user accesses patient records between OFF_HOURS_START
    and OFF_HOURS_END (e.g. 10 PM – 6 AM).

    Severity escalates to HIGH if the access came from a suspicious IP.
    Returns one alert per unique user seen during off-hours.
    """
    cfg    = cfg or {}
    start  = _get(cfg, "off_hours_start", OFF_HOURS_START)
    end    = _get(cfg, "off_hours_end",   OFF_HOURS_END)
    alerts = []

    # Fetch all logs from the last 24 hours
    all_logs = (
        db.query(models.AccessLog)
        .filter(
            models.AccessLog.timestamp >= _utcnow() - timedelta(hours=24)
        )
        .all()
    )

    # Filter to off-hours only
    def is_off_hours(ts: datetime) -> bool:
        hour = ts.hour
        return hour >= start or hour < end

    off_hours_logs = [log for log in all_logs if is_off_hours(log.timestamp)]

    # Group by user so we produce one alert per user, not one per log entry
    user_groups = defaultdict(list)
    for log in off_hours_logs:
        user_groups[log.user].append(log)

    for user, user_logs in user_groups.items():
        sus_ips = [
            log.ip_address for log in user_logs
            if _is_suspicious_ip(log.ip_address)
        ]
        severity = "HIGH" if sus_ips else "MEDIUM"
        ip_note  = (
            f" Access originated from flagged IP(s): {', '.join(set(sus_ips))}."
            if sus_ips else ""
        )

        # Find earliest and latest off-hours access times for context
        times     = sorted([log.timestamp for log in user_logs])
        time_from = times[0].strftime("%H:%M")
        time_to   = times[-1].strftime("%H:%M")

        alerts.append(_make_alert(
            alert_type  = "OFF_HOURS_ACCESS",
            severity    = severity,
            description = (
                f"User '{user}' accessed patient records during off-hours "
                f"({time_from} – {time_to} UTC). "
                f"{len(user_logs)} access event(s) recorded.{ip_note}"
            ),
        ))

    return alerts


# ─── Rule 3: High-Volume Record Viewing ──────────────────────────────────────

def detect_high_volume_access(db: Session, cfg: dict = None) -> list:
    """
    Fires when a single user views an unusually high number of records
    within the look-back window. Could indicate data harvesting.

    Returns one alert per user who exceeds the threshold.
    """
    cfg    = cfg or {}
    limit  = _get(cfg, "high_volume_limit",      HIGH_VOLUME_LIMIT)
    window = _get(cfg, "high_volume_window_min",  HIGH_VOLUME_WINDOW_MIN)
    alerts = []

    view_logs = (
        db.query(models.AccessLog)
        .filter(models.AccessLog.action == HIGH_VOLUME_ACTION)
        .all()
    )

    recent = _logs_within_window(view_logs, window)

    # Count unique patients viewed per user to catch broad sweeping
    user_patient_map = defaultdict(lambda: defaultdict(int))
    for log in recent:
        user_patient_map[log.user][log.patient_id] += 1

    for user, patient_counts in user_patient_map.items():
        total_views     = sum(patient_counts.values())
        unique_patients = len(patient_counts)

        if total_views >= limit:
            severity = "HIGH" if total_views >= limit * 2 else "MEDIUM"

            alerts.append(_make_alert(
                alert_type  = "HIGH_VOLUME_ACCESS",
                severity    = severity,
                description = (
                    f"User '{user}' viewed {total_views} records across "
                    f"{unique_patients} unique patient(s) "
                    f"in the last {window} minutes. "
                    f"Threshold is {limit}. Possible data harvesting."
                ),
            ))

    return alerts


# ─── Rule 4: Suspicious IP Access ────────────────────────────────────────────

def detect_suspicious_ip_access(db: Session, cfg: dict = None) -> list:
    """
    Fires when any access log contains an IP from a known suspicious range.
    Runs over the last 24 hours.
    Returns one alert per unique suspicious IP found.
    """
    cfg     = cfg or {}
    raw     = cfg.get("suspicious_ip_prefixes", "")
    prefixes = [p.strip() for p in raw.split(",") if p.strip()] if raw else SUSPICIOUS_IP_PREFIXES
    alerts  = []

    recent_logs = (
        db.query(models.AccessLog)
        .filter(
            models.AccessLog.timestamp >= _utcnow() - timedelta(hours=24)
        )
        .all()
    )

    def _is_sus(ip: str) -> bool:
        if not ip:
            return False
        return any(ip.startswith(p) for p in prefixes)

    # Group logs by suspicious IP
    ip_groups = defaultdict(list)
    for log in recent_logs:
        if _is_sus(log.ip_address):
            ip_groups[log.ip_address].append(log)

    for ip, ip_logs in ip_groups.items():
        users    = list({log.user for log in ip_logs})
        actions  = list({log.action for log in ip_logs})

        alerts.append(_make_alert(
            alert_type  = "SUSPICIOUS_IP",
            severity    = "HIGH",
            description = (
                f"Access from flagged IP {ip} detected. "
                f"{len(ip_logs)} event(s) involving user(s): {', '.join(users)}. "
                f"Actions performed: {', '.join(actions)}."
            ),
        ))

    return alerts


# ─── Master Runner ────────────────────────────────────────────────────────────

def run_all_detections(db: Session) -> list:
    """
    Runs every detection rule and returns a combined list of alert dicts.
    Call this from a route or a scheduled job to get a live threat summary.

    Each alert dict has keys: alert_type, severity, description, created_at.
    These can be displayed directly on the dashboard or saved to SecurityAlert.
    """
    cfg        = _load_settings(db)
    all_alerts = []

    all_alerts += detect_repeated_failed_access(db, cfg)
    all_alerts += detect_off_hours_access(db, cfg)
    all_alerts += detect_high_volume_access(db, cfg)
    all_alerts += detect_suspicious_ip_access(db, cfg)

    # ML anomaly detection
    try:
        from app.ml_detection import detect as ml_detect
        all_alerts += ml_detect(db, cfg)
    except Exception as e:
        import logging
        logging.getLogger("detection").warning(f"ML detection skipped: {e}")

    # Sort so highest severity appears first
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_alerts.sort(key=lambda a: severity_order.get(a["severity"], 99))

    return all_alerts


def save_detected_alerts(db: Session) -> int:
    """
    Runs all detections and persists any new alerts to the SecurityAlert table.
    Skips duplicates by checking alert_type + description already in the DB.
    Returns the count of newly saved alerts.
    """
    detected = run_all_detections(db)
    saved    = 0

    for alert_data in detected:
        # Check if an identical alert already exists to avoid duplicates
        exists = (
            db.query(models.SecurityAlert)
            .filter(
                models.SecurityAlert.alert_type  == alert_data["alert_type"],
                models.SecurityAlert.description == alert_data["description"],
            )
            .first()
        )

        if not exists:
            new_alert = models.SecurityAlert(**alert_data)
            db.add(new_alert)
            saved += 1
            # Fire email notification for high-severity alerts
            try:
                from app.notifications import notify_alert
                notify_alert(alert_data)
            except Exception:
                pass   # never let a notification failure break detection

    db.commit()
    return saved