from app.core.database import SessionLocal
from collector.collector import run_collection
from app.models.entities import AlertDelivery
from app.services.alerts import deliver_alert_delivery, enqueue_alert_delivery
from worker.celery_app import celery_app


@celery_app.task(name="worker.tasks.collect_threat_intel")
def collect_threat_intel() -> dict:
    with SessionLocal() as db:
        return run_collection(db)


@celery_app.task(
    name="worker.tasks.deliver_alert",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 2},
)
def deliver_alert(delivery_id: int) -> dict:
    with SessionLocal() as db:
        sent = deliver_alert_delivery(db, delivery_id)
        return {"delivery_id": delivery_id, "sent": sent}


@celery_app.task(name="worker.tasks.retry_pending_alerts")
def retry_pending_alerts() -> dict:
    with SessionLocal() as db:
        ids = [
            item.id
            for item in db.query(AlertDelivery)
            .filter(AlertDelivery.status == "pending", AlertDelivery.retry_count < 3)
            .order_by(AlertDelivery.created_at)
            .limit(100)
            .all()
        ]
    for delivery_id in ids:
        enqueue_alert_delivery(delivery_id)
    return {"queued": len(ids)}
