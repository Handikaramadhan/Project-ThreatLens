import base64
import hashlib
from collections.abc import Callable, Iterable

import httpx
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.time import utc_now
from app.models.entities import AlertDelivery, AlertPreference


SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SEVERITY_FILTERED_EVENTS = {"cve", "asset_exposure", "ioc"}
EVENT_FLAG = {
    "news": "notify_news",
    "cve": "notify_cve",
    "asset_exposure": "notify_asset_exposure",
    "ioc": "notify_ioc",
    "source_health": "notify_source_health",
}
EVENT_SEVERITY_FIELD = {
    "cve": "cve_minimum_severity",
    "asset_exposure": "asset_exposure_minimum_severity",
    "ioc": "ioc_minimum_severity",
}


class AlertDeliveryError(RuntimeError):
    pass


def _fernet() -> Fernet:
    if not settings.alert_secret_key:
        raise RuntimeError("ALERT_SECRET_KEY is not configured")
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.alert_secret_key.encode()).digest())
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Stored alert credential cannot be decrypted") from exc


def discord_webhook_hint(encrypted: str) -> str:
    if not encrypted:
        return ""
    try:
        path = decrypt_secret(encrypted).rstrip("/").rsplit("/", 2)
        return f"Webhook …/{path[-2]}" if len(path) >= 2 else "Webhook configured"
    except RuntimeError:
        return "Webhook configured"


def send_telegram(bot_token: str, chat_id: str, message: str, client: httpx.Client | None = None) -> None:
    if not bot_token:
        raise RuntimeError("Telegram bot token belum dikonfigurasi")
    owned = client is None
    client = client or httpx.Client(timeout=15)
    try:
        response = client.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": message[:4096], "disable_web_page_preview": True},
        )
        payload = response.json()
        if response.status_code >= 400:
            detail = payload.get("description") if isinstance(payload, dict) else ""
            suffix = f": {detail}" if detail else ""
            raise AlertDeliveryError(f"Telegram rejected request with HTTP {response.status_code}{suffix}")
        if not payload.get("ok"):
            raise AlertDeliveryError(str(payload.get("description") or "Telegram rejected the message"))
    except httpx.TimeoutException as exc:
        raise AlertDeliveryError("Telegram request timed out") from exc
    except httpx.HTTPError as exc:
        raise AlertDeliveryError("Telegram request failed") from exc
    except ValueError as exc:
        if "response" in locals() and response.status_code >= 400:
            raise AlertDeliveryError(f"Telegram rejected request with HTTP {response.status_code}") from exc
        raise AlertDeliveryError("Telegram returned an invalid response") from exc
    finally:
        if owned:
            client.close()


def send_discord(webhook_url: str, message: str, client: httpx.Client | None = None) -> None:
    owned = client is None
    client = client or httpx.Client(timeout=15)
    try:
        response = client.post(webhook_url, json={"content": message[:2000]})
        if response.status_code >= 400:
            raise AlertDeliveryError(f"Discord rejected request with HTTP {response.status_code}")
    except httpx.TimeoutException as exc:
        raise AlertDeliveryError("Discord request timed out") from exc
    except httpx.HTTPError as exc:
        raise AlertDeliveryError("Discord request failed") from exc
    finally:
        if owned:
            client.close()


def format_alert(title: str, body: str, severity: str) -> str:
    return f"ThreatLens Alert [{severity}]\n{title}\n\n{body}".strip()


def _send_with_retry(send: Callable[[], None], attempts: int = 3) -> int:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            send()
            return attempt + 1
        except Exception as exc:
            last_error = exc
    if last_error:
        raise last_error


def enqueue_alert_delivery(delivery_id: int) -> None:
    try:
        from worker.celery_app import celery_app

        celery_app.send_task("worker.tasks.deliver_alert", args=[delivery_id])
    except Exception:
        # If Redis/Celery is unavailable, leave the delivery pending. The
        # scheduled retry sweep will pick it up when the worker is healthy.
        return


def deliver_test(preference: AlertPreference, channel: str) -> None:
    message = format_alert(
        "Test notification berhasil",
        "Channel ini sudah terhubung ke akun ThreatLens kamu.",
        "Info",
    )
    if channel == "telegram":
        if not preference.telegram_enabled or not preference.telegram_chat_id or not preference.telegram_bot_token_secret:
            raise ValueError("Telegram belum diaktifkan, bot token belum disimpan, atau chat ID belum diisi")
        send_telegram(decrypt_secret(preference.telegram_bot_token_secret), preference.telegram_chat_id, message)
        return
    if channel == "discord":
        if not preference.discord_enabled or not preference.discord_webhook_secret:
            raise ValueError("Discord belum diaktifkan atau webhook belum disimpan")
        send_discord(decrypt_secret(preference.discord_webhook_secret), message)
        return
    raise ValueError("Channel tidak didukung")


def alert_event_key(event_type: str, value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()[:32]
    return f"{event_type}:{digest}"


def queue_alert_event(
    db: Session,
    *,
    event_type: str,
    event_key: str,
    title: str,
    body: str,
    severity: str = "Medium",
    link: str = "",
    state: str = "",
) -> None:
    queued = db.info.setdefault("alert_events", [])
    queued.append(
        {
            "event_type": event_type,
            "event_key": event_key[:255],
            "title": title,
            "body": body,
            "severity": severity if severity in SEVERITY_RANK else "Medium",
            "link": link,
            "state": state,
        }
    )


def flush_alert_events(db: Session, events: Iterable[dict[str, str]] | None = None) -> int:
    queued = list(events if events is not None else db.info.pop("alert_events", []))
    delivered = 0
    seen: set[tuple[str, str]] = set()
    for event in queued:
        key = (event["event_type"], event["event_key"])
        if key in seen:
            continue
        seen.add(key)
        delivered += dispatch_alert_event(db, **event)
    return delivered


def dispatch_alert_event(
    db: Session,
    *,
    event_type: str,
    event_key: str,
    title: str,
    body: str,
    severity: str,
    link: str = "",
    state: str = "",
) -> int:
    flag = EVENT_FLAG.get(event_type)
    if flag is None:
        return 0
    queued = 0
    event_key = event_key[:255]
    preferences = db.scalars(select(AlertPreference).where(AlertPreference.enabled.is_(True))).all()
    for preference in preferences:
        if not getattr(preference, flag):
            continue
        if (
            event_type == "source_health"
            and (preference.source_health_alert_mode or "new_error") == "new_error"
            and state not in {"", "new_error"}
        ):
            continue
        if (
            event_type in SEVERITY_FILTERED_EVENTS
            and SEVERITY_RANK.get(severity, 2)
            < SEVERITY_RANK.get(getattr(preference, EVENT_SEVERITY_FIELD[event_type], preference.minimum_severity), 3)
        ):
            continue
        channels = []
        if preference.telegram_enabled and preference.telegram_chat_id and preference.telegram_bot_token_secret:
            channels.append("telegram")
        if preference.discord_enabled and preference.discord_webhook_secret:
            channels.append("discord")
        for channel in channels:
            exists = db.scalar(
                select(AlertDelivery.id).where(
                    AlertDelivery.user_id == preference.user_id,
                    AlertDelivery.channel == channel,
                    AlertDelivery.event_key == event_key,
                )
            )
            if exists:
                continue
            delivery = AlertDelivery(
                user_id=preference.user_id,
                event_type=event_type,
                event_key=event_key[:255],
                channel=channel,
                title=title[:255],
                body=body,
                link=link[:500],
                severity=severity,
            )
            db.add(delivery)
            try:
                db.flush()
            except IntegrityError:
                db.rollback()
                continue
            db.commit()
            enqueue_alert_delivery(delivery.id)
            queued += 1
    return queued


def deliver_alert_delivery(db: Session, delivery_id: int) -> bool:
    delivery = db.get(AlertDelivery, delivery_id)
    if delivery is None or delivery.status == "sent":
        return False
    preference = db.scalar(select(AlertPreference).where(AlertPreference.user_id == delivery.user_id))
    if preference is None:
        delivery.status = "failed"
        delivery.error = "Alert preference not found"
        db.commit()
        return False

    try:
        message_body = f"{delivery.body}\n\nOpen: {delivery.link}" if delivery.link else delivery.body
        message = format_alert(delivery.title, message_body, delivery.severity)
        if delivery.channel == "telegram":
            attempts = _send_with_retry(
                lambda: send_telegram(
                    decrypt_secret(preference.telegram_bot_token_secret),
                    preference.telegram_chat_id,
                    message,
                )
            )
        elif delivery.channel == "discord":
            attempts = _send_with_retry(
                lambda: send_discord(decrypt_secret(preference.discord_webhook_secret), message)
            )
        else:
            raise AlertDeliveryError("Unsupported alert channel")
        delivery.retry_count += attempts
        delivery.status = "sent"
        delivery.sent_at = utc_now()
        delivery.error = ""
        db.commit()
        return True
    except Exception as exc:
        delivery.retry_count += 1
        delivery.error = str(exc)[:1000]
        delivery.status = "failed" if delivery.retry_count >= 3 else "pending"
        db.commit()
        if delivery.status == "pending":
            raise
        return False
