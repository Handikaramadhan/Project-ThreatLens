from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_id: int | None
    actor_username: str
    action: str
    target_type: str
    target_id: str
    status: str
    ip_address: str
    details: str
    created_at: datetime


class SystemHealthOut(BaseModel):
    service: str
    database: str
    redis: str
    alembic_revision: str
    latest_collection_status: str
    latest_collection_started_at: datetime | None
    latest_collection_finished_at: datetime | None
    audit_events: int
    failed_alert_deliveries: int
