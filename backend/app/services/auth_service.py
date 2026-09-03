import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User, UserSession, utc_now


SESSION_HOURS = 12
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = stored.split("$", 5)
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p)
        ).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user: User, db: Session) -> tuple[str, UserSession]:
    token = secrets.token_urlsafe(32)
    session = UserSession(
        user_id=user.id,
        token_hash=token_digest(token),
        expires_at=utc_now() + timedelta(hours=SESSION_HOURS),
    )
    db.add(session); db.commit(); db.refresh(session)
    return token, session


def session_user(token: str, db: Session) -> User | None:
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_digest(token)))
    if session is None:
        return None
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc) or not session.user.is_active:
        db.delete(session); db.commit()
        return None
    return session.user
