from collections import defaultdict
from datetime import datetime, timedelta
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.entities import AuthSession, User
from app.schemas.auth import AuthResponse, AuthStatus, CreateUserRequest, Credentials, LoginRequest, UserOut
from app.services.auth import (
    AuthContext,
    create_session,
    get_auth_context,
    hash_password,
    require_admin,
    require_admin_csrf,
    require_csrf,
    verify_password,
)

router = APIRouter()
_attempts: dict[str, list[datetime]] = defaultdict(list)
_attempt_lock = Lock()
_dummy_password_hash = hash_password("not-a-real-user-password")


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.rsplit(",", 1)[-1].strip() or (request.client.host if request.client else "unknown")


def _check_rate_limit(key: str) -> None:
    cutoff = datetime.utcnow() - timedelta(minutes=5)
    with _attempt_lock:
        _attempts[key] = [attempt for attempt in _attempts[key] if attempt > cutoff]
        if len(_attempts[key]) >= 5:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts")


def _record_failure(key: str) -> None:
    with _attempt_lock:
        _attempts[key].append(datetime.utcnow())


def _clear_failures(key: str) -> None:
    with _attempt_lock:
        _attempts.pop(key, None)


def _set_session_cookie(response: Response, token: str) -> None:
    max_age = settings.auth_session_hours * 3600
    response.set_cookie(
        key=settings.auth_cookie_name,
        value=token,
        max_age=max_age,
        path="/",
        secure=settings.auth_cookie_secure,
        httponly=True,
        samesite="strict",
    )
    response.headers["Cache-Control"] = "no-store"


def _validate_user_deletion(actor_id: int, target: User | None, admin_count: int) -> User:
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.id == actor_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot delete your own account")
    if target.role == "admin" and admin_count <= 1:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The last admin cannot be deleted")
    return target


@router.get("/auth/status", response_model=AuthStatus)
def auth_status(response: Response, db: Session = Depends(get_db)) -> AuthStatus:
    response.headers["Cache-Control"] = "no-store"
    count = db.scalar(select(func.count()).select_from(User)) or 0
    return AuthStatus(initialized=count > 0)


@router.post("/auth/bootstrap", status_code=201)
def bootstrap_admin(payload: Credentials, db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": 918273645})
    count = db.scalar(select(func.count()).select_from(User)) or 0
    if count:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="System already initialized")

    db.add(User(username=payload.username, password_hash=hash_password(payload.password), role="admin"))
    db.commit()
    return {"status": "created"}


@router.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> AuthResponse:
    key = _client_key(request)
    _check_rate_limit(key)
    username = payload.username.strip().lower()
    user = db.scalar(select(User).where(User.username == username))
    valid, updated_hash = verify_password(
        payload.password,
        user.password_hash if user is not None else _dummy_password_hash,
    )
    if user is None or not valid or not user.active:
        _record_failure(key)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    if updated_hash:
        user.password_hash = updated_hash
        db.commit()
    session, raw_token = create_session(db, user)
    _clear_failures(key)
    _set_session_cookie(response, raw_token)
    return AuthResponse(user=UserOut.model_validate(user), csrf_token=session.csrf_token)


@router.get("/auth/me", response_model=AuthResponse)
def me(response: Response, context: AuthContext = Depends(get_auth_context)) -> AuthResponse:
    response.headers["Cache-Control"] = "no-store"
    return AuthResponse(user=UserOut.model_validate(context.user), csrf_token=context.session.csrf_token)


@router.post("/auth/logout", status_code=204)
def logout(
    response: Response,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> None:
    db.delete(context.session)
    db.commit()
    response.delete_cookie(settings.auth_cookie_name, path="/")
    response.headers["Cache-Control"] = "no-store"


@router.get("/admin/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_admin),
) -> list[User]:
    return list(db.scalars(select(User).order_by(User.created_at)).all())


@router.post("/admin/users", response_model=UserOut, status_code=201)
def create_user(
    payload: CreateUserRequest,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_admin_csrf),
) -> User:
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        created_by=context.user.id,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists") from None
    db.refresh(user)
    return user


@router.delete("/admin/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_admin_csrf),
) -> None:
    db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": 918273646})
    target = db.get(User, user_id)
    admin_count = db.scalar(select(func.count()).select_from(User).where(User.role == "admin")) or 0
    target = _validate_user_deletion(context.user.id, target, admin_count)

    db.execute(update(User).where(User.created_by == target.id).values(created_by=None))
    db.execute(delete(AuthSession).where(AuthSession.user_id == target.id))
    db.delete(target)
    db.commit()
