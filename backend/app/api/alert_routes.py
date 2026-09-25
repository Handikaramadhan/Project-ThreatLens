from collections import defaultdict
from datetime import datetime, timedelta
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.time import utc_now
from app.models.entities import AlertDelivery, AlertPreference
from app.schemas.alerts import (
    AlertDeliveryOut,
    AlertPreferenceOut,
    AlertPreferenceWrite,
    AlertTestRequest,
    AlertTestResponse,
)
from app.services.alerts import (
    decrypt_secret,
    deliver_test,
    discord_webhook_hint,
    encrypt_secret,
    format_alert,
    send_discord,
    send_telegram,
)
from app.services.audit import audit_log
from app.services.auth import AuthContext, get_auth_context, require_csrf


router = APIRouter()
_test_attempts: dict[str, list[datetime]] = defaultdict(list)
_test_attempt_lock = Lock()


def _check_alert_test_rate_limit(user_id: int, channel: str) -> None:
    key = f"{user_id}:{channel}"
    cutoff = utc_now() - timedelta(minutes=5)
    with _test_attempt_lock:
        _test_attempts[key] = [attempt for attempt in _test_attempts[key] if attempt > cutoff]
        if len(_test_attempts[key]) >= 5:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Terlalu banyak test alert")
        _test_attempts[key].append(utc_now())


def _get_or_create(db: Session, user_id: int) -> AlertPreference:
    preference = db.scalar(select(AlertPreference).where(AlertPreference.user_id == user_id))
    if preference is None:
        preference = AlertPreference(user_id=user_id)
        db.add(preference)
        db.commit()
        db.refresh(preference)
    return preference


def _out(preference: AlertPreference) -> AlertPreferenceOut:
    return AlertPreferenceOut(
        enabled=preference.enabled,
        telegram_enabled=preference.telegram_enabled,
        telegram_bot_configured=bool(preference.telegram_bot_token_secret),
        telegram_chat_id=preference.telegram_chat_id,
        discord_enabled=preference.discord_enabled,
        discord_webhook_configured=bool(preference.discord_webhook_secret),
        discord_webhook_hint=discord_webhook_hint(preference.discord_webhook_secret),
        notify_news=preference.notify_news,
        notify_cve=preference.notify_cve,
        notify_asset_exposure=preference.notify_asset_exposure,
        notify_ioc=preference.notify_ioc,
        notify_source_health=preference.notify_source_health,
        minimum_severity=preference.minimum_severity,
        cve_minimum_severity=preference.cve_minimum_severity or preference.minimum_severity,
        asset_exposure_minimum_severity=preference.asset_exposure_minimum_severity or preference.minimum_severity,
        ioc_minimum_severity=preference.ioc_minimum_severity or preference.minimum_severity,
        source_health_alert_mode=preference.source_health_alert_mode or "new_error",
        updated_at=preference.updated_at,
    )


@router.get("/alerts/preferences", response_model=AlertPreferenceOut)
def get_preferences(
    response: Response,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(get_auth_context),
) -> AlertPreferenceOut:
    response.headers["Cache-Control"] = "no-store"
    return _out(_get_or_create(db, context.user.id))


@router.put("/alerts/preferences", response_model=AlertPreferenceOut)
def update_preferences(
    payload: AlertPreferenceWrite,
    request: Request,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> AlertPreferenceOut:
    preference = _get_or_create(db, context.user.id)
    if payload.telegram_enabled and not payload.telegram_bot_token and not preference.telegram_bot_token_secret:
        raise HTTPException(status_code=422, detail="Telegram bot token wajib diisi")
    if payload.discord_enabled and not payload.discord_webhook_url and not preference.discord_webhook_secret:
        raise HTTPException(status_code=422, detail="Discord webhook wajib diisi")
    for field in (
        "enabled", "telegram_enabled", "telegram_chat_id", "discord_enabled",
        "notify_news", "notify_cve", "notify_asset_exposure", "notify_ioc",
        "notify_source_health", "minimum_severity", "cve_minimum_severity",
        "asset_exposure_minimum_severity", "ioc_minimum_severity",
        "source_health_alert_mode",
    ):
        setattr(preference, field, getattr(payload, field))
    if payload.clear_telegram_bot_token:
        preference.telegram_bot_token_secret = ""
        preference.telegram_enabled = False
    elif payload.telegram_bot_token:
        try:
            preference.telegram_bot_token_secret = encrypt_secret(payload.telegram_bot_token)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    if payload.clear_discord_webhook:
        preference.discord_webhook_secret = ""
        preference.discord_enabled = False
    elif payload.discord_webhook_url:
        try:
            preference.discord_webhook_secret = encrypt_secret(payload.discord_webhook_url)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    preference.updated_at = utc_now()
    audit_log(
        db,
        action="alert.preferences.update",
        actor=context.user,
        request=request,
        target_type="alert_preferences",
        target_id=str(preference.id),
        details={
            "enabled": payload.enabled,
            "telegram_enabled": payload.telegram_enabled,
            "telegram_token_changed": bool(payload.telegram_bot_token or payload.clear_telegram_bot_token),
            "discord_enabled": payload.discord_enabled,
            "discord_webhook_changed": bool(payload.discord_webhook_url or payload.clear_discord_webhook),
        },
    )
    db.commit()
    db.refresh(preference)
    return _out(preference)


@router.post("/alerts/test", response_model=AlertTestResponse)
def test_alert(
    payload: AlertTestRequest,
    request: Request,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> AlertTestResponse:
    _check_alert_test_rate_limit(context.user.id, payload.channel)
    preference = _get_or_create(db, context.user.id)
    try:
        message = format_alert(
            "Test notification berhasil",
            "Channel ini sudah terhubung ke akun ThreatLens kamu.",
            "Info",
        )
        if payload.channel == "telegram" and (payload.telegram_bot_token or payload.telegram_chat_id):
            token = payload.telegram_bot_token or (
                decrypt_secret(preference.telegram_bot_token_secret) if preference.telegram_bot_token_secret else ""
            )
            chat_id = payload.telegram_chat_id or preference.telegram_chat_id
            if not token or not chat_id:
                raise ValueError("Telegram bot token dan chat ID wajib diisi")
            send_telegram(token, chat_id, message)
        elif payload.channel == "discord" and payload.discord_webhook_url:
            send_discord(payload.discord_webhook_url, message)
        else:
            deliver_test(preference, payload.channel)
        audit_log(
            db,
            action="alert.test",
            actor=context.user,
            request=request,
            target_type="alert_channel",
            target_id=payload.channel,
            status="success",
            details={"channel": payload.channel, "used_unsaved_value": bool(payload.telegram_bot_token or payload.telegram_chat_id or payload.discord_webhook_url)},
            commit=True,
        )
    except ValueError as exc:
        audit_log(
            db,
            action="alert.test",
            actor=context.user,
            request=request,
            target_type="alert_channel",
            target_id=payload.channel,
            status="failed",
            details={"channel": payload.channel, "reason": str(exc)[:240]},
            commit=True,
        )
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        audit_log(
            db,
            action="alert.test",
            actor=context.user,
            request=request,
            target_type="alert_channel",
            target_id=payload.channel,
            status="failed",
            details={"channel": payload.channel, "reason": str(exc)[:240]},
            commit=True,
        )
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return AlertTestResponse(status="sent", channel=payload.channel)


@router.get("/alerts/deliveries", response_model=list[AlertDeliveryOut])
def list_deliveries(
    db: Session = Depends(get_db),
    context: AuthContext = Depends(get_auth_context),
) -> list[AlertDelivery]:
    return list(
        db.scalars(
            select(AlertDelivery)
            .where(AlertDelivery.user_id == context.user.id)
            .order_by(desc(AlertDelivery.created_at))
            .limit(100)
        ).all()
    )
