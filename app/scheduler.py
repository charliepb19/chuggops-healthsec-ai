# app/scheduler.py
# Background scheduler — runs the detection engine automatically every 15 minutes.
# Uses APScheduler's AsyncIOScheduler so it shares FastAPI's event loop.

import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.database import SessionLocal
from app.detection import save_detected_alerts

logger    = logging.getLogger("scheduler")
scheduler = AsyncIOScheduler(timezone="UTC")


def _detection_job():
    """Runs on the scheduler thread — owns its own DB session."""
    db = SessionLocal()
    try:
        count = save_detected_alerts(db)
        if count:
            logger.info(f"Auto-detection: {count} new alert(s) saved.")
    except Exception as e:
        logger.error(f"Auto-detection failed: {e}")
    finally:
        db.close()


def _ml_train_job():
    """Retrains the Isolation Forest model daily at 02:00 UTC."""
    db = SessionLocal()
    try:
        from app.ml_detection import train
        ok = train(db)
        if ok:
            logger.info("Daily ML model retrain succeeded.")
        else:
            logger.warning("Daily ML retrain skipped — insufficient data.")
    except Exception as e:
        logger.error(f"Daily ML retrain failed: {e}")
    finally:
        db.close()


def start():
    """Register jobs and start the scheduler. Call once on app startup."""
    scheduler.add_job(
        _detection_job,
        trigger          = "interval",
        minutes          = 15,
        id               = "auto_detection",
        replace_existing = True,
    )
    scheduler.add_job(
        _ml_train_job,
        trigger          = "cron",
        hour             = 2,
        minute           = 0,
        id               = "ml_daily_train",
        replace_existing = True,
    )
    scheduler.start()
    logger.info("Scheduler started — detection every 15 min, ML retrain daily at 02:00 UTC.")


def stop():
    """Gracefully shut down. Call on app shutdown."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
