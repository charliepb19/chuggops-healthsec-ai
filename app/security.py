# app/security.py
# Security utilities: brute-force tracking and password validation.

from collections import defaultdict
from datetime import datetime, timedelta

# ── Brute-force / account lockout ────────────────────────────────────────────

LOCKOUT_ATTEMPTS = 5    # failed attempts before lockout
LOCKOUT_MINUTES  = 15   # how long the lockout lasts

# In-memory store: username → list of failure datetimes
# Resets on server restart, which is acceptable for a single-server deployment.
_failures: dict[str, list] = defaultdict(list)


def _prune(username: str) -> list:
    """Remove failure records older than the lockout window."""
    cutoff = datetime.utcnow() - timedelta(minutes=LOCKOUT_MINUTES)
    _failures[username] = [t for t in _failures[username] if t > cutoff]
    return _failures[username]


def is_locked_out(username: str) -> tuple[bool, int]:
    """
    Returns (locked, minutes_remaining).
    locked=True means the account is currently in lockout.
    """
    recent = _prune(username)
    if len(recent) >= LOCKOUT_ATTEMPTS:
        oldest_in_window = min(recent)
        unlock_at = oldest_in_window + timedelta(minutes=LOCKOUT_MINUTES)
        remaining = max(0, int((unlock_at - datetime.utcnow()).total_seconds() / 60) + 1)
        return True, remaining
    return False, 0


def record_failure(username: str) -> None:
    """Record a failed login attempt."""
    _prune(username)
    _failures[username].append(datetime.utcnow())


def clear_failures(username: str) -> None:
    """Clear failure history after a successful login."""
    _failures.pop(username, None)


# ── Password validation ───────────────────────────────────────────────────────

MIN_LENGTH = 8


def validate_password(password: str) -> list[str]:
    """
    Returns a list of validation errors.
    Empty list means the password is acceptable.
    """
    errors = []
    if len(password) < MIN_LENGTH:
        errors.append(f"Password must be at least {MIN_LENGTH} characters.")
    if password.isalpha():
        errors.append("Password must contain at least one number or symbol.")
    if password.lower() in ("password", "password1", "admin", "admin123", "12345678"):
        errors.append("Password is too common.")
    return errors
