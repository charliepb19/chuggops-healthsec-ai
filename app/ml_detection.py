# app/ml_detection.py
# ML-based anomaly detection using Isolation Forest.
#
# Learns what "normal" access behaviour looks like for the hospital as a whole,
# then flags events that deviate significantly from that baseline.
#
# Why Isolation Forest?
#   - Works well on small datasets (no minimum sample size for inference)
#   - Unsupervised — no labelled "attack" data needed
#   - Interpretable contamination parameter (expected % of anomalies)
#   - Fast enough to run every 15 minutes alongside the rule-based engine

import logging
import os
import numpy as np
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("ml_detection")

ACTION_MAP   = {"VIEW": 0, "EDIT": 1, "DELETE": 2, "PRINT": 3, "EXPORT": 4}
MIN_SAMPLES  = 50    # skip training if fewer rows than this
WINDOW_MIN   = 60    # look-back window for scoring new events

# Where to persist the trained model between container restarts
MODEL_PATH = os.getenv("ML_MODEL_PATH", "models/isolation_forest.pkl")

# Module-level model cache — survives between scheduler runs
_model        = None
_trained_at   = None
_sample_count = 0


def _save_model() -> None:
    """Persist the current model to disk so it survives container restarts."""
    try:
        import joblib
        os.makedirs(os.path.dirname(MODEL_PATH) or ".", exist_ok=True)
        joblib.dump(
            {"model": _model, "trained_at": _trained_at, "sample_count": _sample_count},
            MODEL_PATH,
        )
        logger.info(f"ML model saved to {MODEL_PATH}.")
    except Exception as e:
        logger.warning(f"Could not save ML model: {e}")


def _load_model() -> None:
    """Load a previously saved model from disk on startup."""
    global _model, _trained_at, _sample_count
    if not os.path.exists(MODEL_PATH):
        return
    try:
        import joblib
        data          = joblib.load(MODEL_PATH)
        _model        = data["model"]
        _trained_at   = data["trained_at"]
        _sample_count = data["sample_count"]
        logger.info(f"ML model loaded from {MODEL_PATH} ({_sample_count} samples).")
    except Exception as e:
        logger.warning(f"Could not load ML model from disk: {e}")


# Attempt to restore from disk as soon as the module is imported
_load_model()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _to_features(logs: list) -> "np.ndarray | None":
    """
    Convert a list of AccessLog objects to a 2-D feature matrix.

    Features per event:
        hour           — time of day (0–23)
        day_of_week    — Monday=0 … Sunday=6
        action_encoded — VIEW=0, EDIT=1, DELETE=2, PRINT=3, EXPORT=4, other=5
        is_off_hours   — 1 if hour ≥ 22 or hour < 6, else 0
        is_weekend     — 1 if Saturday or Sunday, else 0
    """
    rows = []
    for log in logs:
        if not log.timestamp:
            continue
        ts  = log.timestamp
        act = ACTION_MAP.get((log.action or "").upper(), 5)
        rows.append([
            ts.hour,
            ts.weekday(),
            act,
            1 if (ts.hour >= 22 or ts.hour < 6) else 0,
            1 if ts.weekday() >= 5 else 0,
        ])
    return np.array(rows, dtype=float) if rows else None


def train(db, contamination: float = 0.05) -> bool:
    """
    Train an Isolation Forest on the last 90 days of access logs.

    Args:
        db            — SQLAlchemy session
        contamination — expected fraction of anomalies (0.01–0.20)

    Returns True if training succeeded, False if insufficient data.
    """
    global _model, _trained_at, _sample_count

    from app.models import AccessLog
    cutoff = _utcnow() - timedelta(days=90)
    logs   = db.query(AccessLog).filter(AccessLog.timestamp >= cutoff).all()

    if len(logs) < MIN_SAMPLES:
        logger.warning(
            f"ML training skipped — {len(logs)} samples available, "
            f"need at least {MIN_SAMPLES}."
        )
        return False

    X = _to_features(logs)
    if X is None or len(X) < MIN_SAMPLES:
        return False

    try:
        from sklearn.ensemble import IsolationForest
        clf = IsolationForest(
            n_estimators  = 100,
            contamination = float(contamination),
            random_state  = 42,
            n_jobs        = -1,
        )
        clf.fit(X)
        _model        = clf
        _trained_at   = _utcnow()
        _sample_count = len(X)
        logger.info(f"ML model trained on {len(X)} samples (contamination={contamination}).")
        _save_model()
        return True
    except Exception as e:
        logger.error(f"ML training failed: {e}")
        return False


def detect(db, cfg: dict = None) -> list[dict]:
    """
    Score access events from the last WINDOW_MIN minutes.
    Returns a list of alert dicts for any anomalous users found.

    Auto-trains the model on first call or if the cached model is >24h old.
    """
    global _model, _trained_at

    settings     = cfg or {}
    enabled      = settings.get("ml_detection_enabled", "true").lower() == "true"
    contamination = float(settings.get("ml_contamination", "0.05"))

    if not enabled:
        return []

    # Auto-train if stale or missing
    stale = (
        _model is None
        or _trained_at is None
        or (_utcnow() - _trained_at) > timedelta(hours=24)
    )
    if stale:
        if not train(db, contamination):
            return []

    from app.models import AccessLog
    from collections import defaultdict

    cutoff      = _utcnow() - timedelta(minutes=WINDOW_MIN)
    recent_logs = db.query(AccessLog).filter(AccessLog.timestamp >= cutoff).all()
    if not recent_logs:
        return []

    X = _to_features(recent_logs)
    if X is None:
        return []

    scores    = _model.score_samples(X)          # more negative = more anomalous
    threshold = np.percentile(scores, contamination * 100)

    # Group anomalous events by user for one alert per user
    flagged_by_user = defaultdict(list)
    for log, score in zip(recent_logs, scores):
        if score <= threshold:
            flagged_by_user[log.user].append((log, float(score)))

    alerts = []
    for user, items in flagged_by_user.items():
        actions   = sorted({l.action for l, _ in items})
        min_score = min(s for _, s in items)
        severity  = "HIGH" if min_score < threshold * 1.5 else "MEDIUM"

        alerts.append({
            "alert_type":  "ML_ANOMALY",
            "severity":    severity,
            "description": (
                f"ML anomaly detector flagged unusual behaviour for user '{user}'. "
                f"{len(items)} anomalous event(s) in the last {WINDOW_MIN} minutes. "
                f"Actions: {', '.join(actions)}. "
                f"Anomaly score: {min_score:.4f} (threshold: {threshold:.4f}). "
                f"This pattern deviates significantly from the {_sample_count}-event "
                f"baseline the model was trained on."
            ),
            "created_at": _utcnow(),
        })

    return alerts


def status() -> dict:
    """Returns current model state — used by the settings page."""
    return {
        "trained":      _model is not None,
        "trained_at":   _trained_at,
        "sample_count": _sample_count,
        "model_type":   "Isolation Forest (sklearn)" if _model else None,
    }
