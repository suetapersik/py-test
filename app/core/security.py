"""Password hashing, JWT creation/decoding and datetime helpers."""

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def utcnow() -> datetime:
    """Timezone-aware UTC now. Single source of 'current time' for the app."""
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime) -> datetime:
    """Treat naive datetimes (e.g. from SQLite) as UTC so comparisons never raise."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def hash_password(password: str) -> str:
    # bcrypt only uses the first 72 bytes; truncate to avoid errors on long passwords.
    return pwd_context.hash(password[:72])


def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Truncate before verify so it matches the stored hash created from password[:72].
    return pwd_context.verify(plain_password[:72], hashed_password)


def _create_token(user_id: int, token_type: str, expires_delta: timedelta) -> str:
    payload = {
        "sub": str(user_id),
        "exp": utcnow() + expires_delta,
        "type": token_type,
        # jti keeps tokens unique even when two are minted in the same second.
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def create_access_token(user_id: int) -> str:
    return _create_token(user_id, "access", timedelta(minutes=settings.access_token_expire_minutes))


def create_refresh_token(user_id: int) -> str:
    return _create_token(user_id, "refresh", timedelta(days=settings.refresh_token_expire_days))


def decode_token(token: str) -> dict:
    """Decode and validate a JWT (signature + exp). Raises 401 on any failure."""
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
