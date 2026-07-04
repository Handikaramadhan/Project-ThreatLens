from celery import Celery

from app.core.config import settings

celery_app = Celery("threatlens", broker=settings.redis_url, backend=settings.redis_url, include=["worker.tasks"])
celery_app.conf.timezone = "Asia/Jakarta"
celery_app.conf.broker_connection_retry_on_startup = True
celery_app.conf.beat_schedule = {
    "collect-threat-intel-every-hour": {
        "task": "worker.tasks.collect_threat_intel",
        "schedule": 3600.0,
    }
}
