from app.core.database import SessionLocal
from collector.collector import run_collection
from worker.celery_app import celery_app


@celery_app.task(name="worker.tasks.collect_threat_intel")
def collect_threat_intel() -> dict:
    with SessionLocal() as db:
        return run_collection(db)
