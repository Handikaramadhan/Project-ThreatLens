from datetime import datetime
import re
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Severity = Literal["Low", "Medium", "High", "Critical"]
SourceHealthAlertMode = Literal["new_error", "every_error"]


class AlertPreferenceWrite(BaseModel):
    enabled: bool = False
    telegram_enabled: bool = False
    telegram_bot_token: str = Field(default="", max_length=160)
    clear_telegram_bot_token: bool = False
    telegram_chat_id: str = Field(default="", max_length=80)
    discord_enabled: bool = False
    discord_webhook_url: str = Field(default="", max_length=600)
    clear_discord_webhook: bool = False
    notify_news: bool = True
    notify_cve: bool = True
    notify_asset_exposure: bool = True
    notify_ioc: bool = False
    notify_source_health: bool = True
    minimum_severity: Severity = "High"
    cve_minimum_severity: Severity = "High"
    asset_exposure_minimum_severity: Severity = "High"
    ioc_minimum_severity: Severity = "High"
    source_health_alert_mode: SourceHealthAlertMode = "new_error"

    @field_validator("telegram_chat_id")
    @classmethod
    def validate_chat_id(cls, value: str) -> str:
        value = value.strip()
        if value and not value.removeprefix("-").isdigit():
            raise ValueError("Telegram chat ID harus berupa angka")
        return value

    @field_validator("telegram_bot_token")
    @classmethod
    def validate_telegram_bot_token(cls, value: str) -> str:
        value = value.strip()
        if value and not re.fullmatch(r"\d{5,20}:[A-Za-z0-9_-]{20,}", value):
            raise ValueError("Telegram bot token tidak valid")
        return value

    @field_validator("discord_webhook_url")
    @classmethod
    def validate_discord_webhook(cls, value: str) -> str:
        value = value.strip()
        if not value:
            return value
        parsed = urlparse(value)
        if parsed.scheme != "https" or parsed.hostname not in {"discord.com", "discordapp.com"}:
            raise ValueError("Gunakan URL webhook Discord resmi dengan HTTPS")
        if not parsed.path.startswith("/api/webhooks/"):
            raise ValueError("URL webhook Discord tidak valid")
        return value

    @model_validator(mode="after")
    def validate_enabled_channels(self) -> "AlertPreferenceWrite":
        if self.enabled and not (self.telegram_enabled or self.discord_enabled):
            raise ValueError("Aktifkan minimal satu channel")
        if self.telegram_enabled and not self.telegram_chat_id:
            raise ValueError("Telegram chat ID wajib diisi")
        return self


class AlertPreferenceOut(BaseModel):
    enabled: bool
    telegram_enabled: bool
    telegram_bot_configured: bool
    telegram_chat_id: str
    discord_enabled: bool
    discord_webhook_configured: bool
    discord_webhook_hint: str
    notify_news: bool
    notify_cve: bool
    notify_asset_exposure: bool
    notify_ioc: bool
    notify_source_health: bool
    minimum_severity: Severity
    cve_minimum_severity: Severity
    asset_exposure_minimum_severity: Severity
    ioc_minimum_severity: Severity
    source_health_alert_mode: SourceHealthAlertMode
    updated_at: datetime | None


class AlertDeliveryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_type: str
    channel: str
    title: str
    severity: str
    status: str
    retry_count: int = 0
    error: str
    created_at: datetime
    sent_at: datetime | None


class AlertTestRequest(BaseModel):
    channel: Literal["telegram", "discord"]
    telegram_bot_token: str = Field(default="", max_length=160)
    telegram_chat_id: str = Field(default="", max_length=80)
    discord_webhook_url: str = Field(default="", max_length=600)

    @field_validator("telegram_bot_token")
    @classmethod
    def validate_test_telegram_bot_token(cls, value: str) -> str:
        return AlertPreferenceWrite.validate_telegram_bot_token(value)

    @field_validator("telegram_chat_id")
    @classmethod
    def validate_test_chat_id(cls, value: str) -> str:
        return AlertPreferenceWrite.validate_chat_id(value)

    @field_validator("discord_webhook_url")
    @classmethod
    def validate_test_discord_webhook(cls, value: str) -> str:
        return AlertPreferenceWrite.validate_discord_webhook(value)


class AlertTestResponse(BaseModel):
    status: Literal["sent"]
    channel: Literal["telegram", "discord"]
