from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditEvent, AutomationEvent, User, UserSession
from app.schemas import AuditEventRead, AuthSessionCreated, AuthStatus, LoginRequest, SetupRequest, UserCreate, UserRead, UserUpdate
from app.services.auth_service import create_session, hash_password, session_user, token_digest, verify_password

router = APIRouter(prefix="/api/auth", tags=["authentication"])


def bearer_token(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return authorization[7:].strip() or None


def require_admin(request: Request) -> User:
    user = getattr(request.state, "user", None)
    if user is None or user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user


@router.get("/status", response_model=AuthStatus)
def auth_status(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> AuthStatus:
    setup_required = (db.scalar(select(func.count(User.id))) or 0) == 0
    token = bearer_token(authorization)
    user = session_user(token, db) if token else None
    return AuthStatus(setup_required=setup_required, authenticated=user is not None, user=user)


@router.post("/setup", response_model=AuthSessionCreated, status_code=201)
def setup_admin(payload: SetupRequest, db: Session = Depends(get_db)) -> AuthSessionCreated:
    if (db.scalar(select(func.count(User.id))) or 0) != 0:
        raise HTTPException(status_code=409, detail="Initial setup has already been completed")
    user = User(username=payload.username.lower(), password_hash=hash_password(payload.password), role="ADMIN")
    db.add(user); db.commit(); db.refresh(user)
    token, session = create_session(user, db)
    return AuthSessionCreated(token=token, expires_at=session.expires_at, user=user)


@router.post("/login", response_model=AuthSessionCreated)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> AuthSessionCreated:
    user = db.scalar(select(User).where(User.username == payload.username.strip().lower()))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        db.add(AutomationEvent(
            event_type="AUTHENTICATION_FAILURE",
            severity="WARNING",
            message=f"Failed sign-in attempt for {payload.username.strip().lower()[:80]}.",
        ))
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token, session = create_session(user, db)
    return AuthSessionCreated(token=token, expires_at=session.expires_at, user=user)


@router.post("/logout", status_code=204)
def logout(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> Response:
    token = bearer_token(authorization)
    if token:
        session = db.scalar(select(UserSession).where(UserSession.token_hash == token_digest(token)))
        if session is not None:
            db.delete(session); db.commit()
    return Response(status_code=204)


@router.get("/users", response_model=list[UserRead], dependencies=[Depends(require_admin)])
def list_users(db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.username)))


@router.post("/users", response_model=UserRead, status_code=201, dependencies=[Depends(require_admin)])
def create_user(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    user = User(username=payload.username.lower(), password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    try: db.commit()
    except IntegrityError as exc:
        db.rollback(); raise HTTPException(status_code=409, detail="Username already exists") from exc
    db.refresh(user); return user


@router.put("/users/{user_id}", response_model=UserRead, dependencies=[Depends(require_admin)])
def update_user(user_id: int, payload: UserUpdate, db: Session = Depends(get_db)) -> User:
    user = db.get(User, user_id)
    if user is None: raise HTTPException(status_code=404, detail="User not found")
    if user.role == "ADMIN" and user.is_active and (payload.role != "ADMIN" or not payload.is_active):
        active_admins = db.scalar(select(func.count(User.id)).where(User.role == "ADMIN", User.is_active.is_(True))) or 0
        if active_admins <= 1:
            raise HTTPException(status_code=409, detail="The last active administrator cannot be demoted or disabled")
    user.role = payload.role; user.is_active = payload.is_active
    if payload.password: user.password_hash = hash_password(payload.password)
    if not user.is_active or payload.password:
        for session in list(user.sessions): db.delete(session)
    db.commit(); db.refresh(user); return user


@router.get("/audit-events", response_model=list[AuditEventRead], dependencies=[Depends(require_admin)])
def list_audit_events(
    limit: int = Query(default=200, ge=1, le=1000), db: Session = Depends(get_db)
) -> list[AuditEvent]:
    return list(db.scalars(select(AuditEvent).order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc()).limit(limit)))
