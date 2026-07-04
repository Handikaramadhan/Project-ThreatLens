import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import Depends, Header, HTTPException, Request, status
from pwdlib import PasswordHash
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.entities import AuthSession, User

password_hash = PasswordHash.recommended()


@dataclass(frozen=True)
class AuthContext:
    user: User
    session: AuthSession


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, encoded_hash: str) -> tuple[bool, str | None]:
    return password_hash.verify_and_update(password, encoded_hash)


def session_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(db: Session, user: User) -> tuple[AuthSession, str]:
    now = datetime.utcnow()
    db.execute(delete(AuthSession).where(AuthSession.expires_at <= now))
    raw_token = secrets.token_urlsafe(48)
    session = AuthSession(
        user_id=user.id,
        token_hash=session_token_hash(raw_token),
        csrf_token=secrets.token_urlsafe(32),
        expires_at=now + timedelta(hours=settings.auth_session_hours),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session, raw_token


def get_auth_context(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    raw_token = request.cookies.get(settings.auth_cookie_name)
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    session = db.scalar(
        select(AuthSession).where(AuthSession.token_hash == session_token_hash(raw_token))
    )
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    if session.expires_at <= datetime.utcnow():
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    user = db.get(User, session.user_id)
    if user is None or not user.active:
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account unavailable")
    return AuthContext(user=user, session=session)


def require_csrf(
    context: AuthContext = Depends(get_auth_context),
    x_csrf_token: str | None = Header(default=None),
) -> AuthContext:
    if not x_csrf_token or not hmac.compare_digest(x_csrf_token, context.session.csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")
    return context


def require_admin(context: AuthContext = Depends(get_auth_context)) -> AuthContext:
    if context.user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin permission required")
    return context


def require_admin_csrf(
    context: AuthContext = Depends(require_csrf),
) -> AuthContext:
    if context.user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin permission required")
    return context
