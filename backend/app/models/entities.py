from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.time import utc_now


class CVE(Base):
    __tablename__ = "cve"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    vendor: Mapped[str] = mapped_column(String(120), index=True)
    product: Mapped[str] = mapped_column(String(120), default="")
    cvss_score: Mapped[float] = mapped_column(Float, default=0)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    published_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    source: Mapped[str] = mapped_column(String(120), default="seed")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)


class CVEDetail(Base):
    __tablename__ = "cve_details"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    nvd_payload: Mapped[str] = mapped_column(Text, default="{}")
    kev_payload: Mapped[str] = mapped_column(Text, default="{}")
    nvd_fetched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kev_fetched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class CVEWebEnrichment(Base):
    __tablename__ = "cve_web_enrichment"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    payload: Mapped[str] = mapped_column(Text, default="{}")
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IOC(Base):
    __tablename__ = "ioc"
    __table_args__ = (UniqueConstraint("indicator", "type", name="uq_ioc_indicator_type"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator: Mapped[str] = mapped_column(String(255), index=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    threat: Mapped[str] = mapped_column(String(120), default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    source: Mapped[str] = mapped_column(String(120), default="seed")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utc_now)


class ThreatNews(Base):
    __tablename__ = "threat_news"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(String(500), unique=True)
    source: Mapped[str] = mapped_column(String(120))
    published_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    summary: Mapped[str] = mapped_column(Text, default="")


class MitreTechnique(Base):
    __tablename__ = "mitre_attack"

    id: Mapped[int] = mapped_column(primary_key=True)
    technique_id: Mapped[str] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    tactic: Mapped[str] = mapped_column(String(80), index=True)
    count: Mapped[int] = mapped_column(Integer, default=0)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    asset_type: Mapped[str] = mapped_column(String(80))
    os_version: Mapped[str] = mapped_column(String(120), default="")
    vendor: Mapped[str] = mapped_column(String(120), default="")
    product: Mapped[str] = mapped_column(String(120), default="")
    version: Mapped[str] = mapped_column(String(80), default="")
    environment: Mapped[str] = mapped_column(String(40), default="")
    criticality: Mapped[str] = mapped_column(String(16), default="Medium")
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    owner: Mapped[str] = mapped_column(String(120), default="")
    risk: Mapped[str] = mapped_column(String(16), default="Low")
    exposures: Mapped[list["AssetExposure"]] = relationship(back_populates="asset")


class AssetExposure(Base):
    __tablename__ = "asset_exposures"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    matching_score: Mapped[int] = mapped_column(Integer, default=0)
    risk: Mapped[str] = mapped_column(String(16), default="Low")
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    review_note: Mapped[str] = mapped_column(Text, default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reviewed_by: Mapped[str] = mapped_column(String(64), default="")
    asset: Mapped[Asset] = relationship(back_populates="exposures")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    channel: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    severity: Mapped[str] = mapped_column(String(16), default="Medium")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)


class AlertPreference(Base):
    __tablename__ = "alert_preferences"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    telegram_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    telegram_bot_token_secret: Mapped[str] = mapped_column(Text, default="")
    telegram_chat_id: Mapped[str] = mapped_column(String(80), default="")
    discord_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    discord_webhook_secret: Mapped[str] = mapped_column(Text, default="")
    notify_news: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_cve: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_asset_exposure: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_ioc: Mapped[bool] = mapped_column(Boolean, default=False)
    notify_source_health: Mapped[bool] = mapped_column(Boolean, default=True)
    minimum_severity: Mapped[str] = mapped_column(String(16), default="High")
    cve_minimum_severity: Mapped[str] = mapped_column(String(16), default="High")
    asset_exposure_minimum_severity: Mapped[str] = mapped_column(String(16), default="High")
    ioc_minimum_severity: Mapped[str] = mapped_column(String(16), default="High")
    source_health_alert_mode: Mapped[str] = mapped_column(String(24), default="new_error")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)


class AlertDelivery(Base):
    __tablename__ = "alert_deliveries"
    __table_args__ = (
        UniqueConstraint("user_id", "channel", "event_key", name="uq_alert_delivery_user_channel_event"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    event_key: Mapped[str] = mapped_column(String(255))
    channel: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text, default="")
    link: Mapped[str] = mapped_column(String(500), default="")
    severity: Mapped[str] = mapped_column(String(16), default="Medium")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    actor_username: Mapped[str] = mapped_column(String(64), default="", index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    target_type: Mapped[str] = mapped_column(String(80), default="", index=True)
    target_id: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(32), default="success", index=True)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)


class CollectionRun(Base):
    __tablename__ = "collection_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    details: Mapped[str] = mapped_column(Text, default="{}")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="user", index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")


class AIConversation(Base):
    __tablename__ = "ai_conversations"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String(160), default="New investigation")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)
    messages: Mapped[list["AIMessage"]] = relationship(
        back_populates="conversation",
        cascade="all, delete-orphan",
    )


class AIMessage(Base):
    __tablename__ = "ai_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    conversation_id: Mapped[int] = mapped_column(
        ForeignKey("ai_conversations.id", ondelete="CASCADE"),
        index=True,
    )
    role: Mapped[str] = mapped_column(String(16))
    content: Mapped[str] = mapped_column(Text)
    citations: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    conversation: Mapped[AIConversation] = relationship(back_populates="messages")


class CVEAIEnrichment(Base):
    __tablename__ = "cve_ai_enrichment"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    payload: Mapped[str] = mapped_column(Text, default="{}")
    provider: Mapped[str] = mapped_column(String(80), default="")
    model: Mapped[str] = mapped_column(String(120), default="")
    confidence: Mapped[float] = mapped_column(Float, default=0)
    generated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
