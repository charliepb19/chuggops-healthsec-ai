# app/auth.py
# Database-backed authentication for ChuggOps HealthSec AI.
#
# Passwords are hashed with PBKDF2-HMAC-SHA256.
# On first startup the admin user is seeded from environment variables:
#   CHUGGOPS_ADMIN_USER  (default: admin)
#   CHUGGOPS_ADMIN_PASS  (default: admin)

import hashlib
import os
from datetime import datetime, timezone
from sqlalchemy.orm import Session

_SALT = b"chuggops-healthsec-ai-v1"


def hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), _SALT, 260_000).hex()


def verify(username: str, password: str, db: Session):
    """
    Returns the User object if credentials are valid and account is active.
    Returns None otherwise.
    """
    from app.models import User
    user = db.query(User).filter(
        User.username == username,
        User.active   == True,
    ).first()
    if not user:
        return None
    if user.hashed_password == hash_password(password):
        return user
    return None


def seed_admin(db: Session) -> None:
    """
    Creates the default admin account from env vars if no users exist yet.
    Safe to call on every startup — no-op if users already exist.
    """
    from app.models import User
    if db.query(User).count() > 0:
        return
    admin = User(
        username        = os.getenv("CHUGGOPS_ADMIN_USER", "admin"),
        hashed_password = hash_password(os.getenv("CHUGGOPS_ADMIN_PASS", "admin")),
        role            = "ADMIN",
        active          = True,
        created_at      = datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(admin)
    db.commit()
