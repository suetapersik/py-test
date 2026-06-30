import random
import string
from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    ensure_aware,
    hash_password,
    utcnow,
    verify_password,
)
from app.modules.auth.models import RefreshToken
from app.modules.users.models import User
from app.modules.users.schemas import UserCreate

VERIFICATION_CODE_TTL_MINUTES = 15


def _generate_verification_code() -> str:
    return "".join(random.choices(string.digits, k=6))


async def register_user(session: AsyncSession, data: UserCreate) -> str:
    existing = await session.scalar(select(User).where(User.email == data.email))
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    code = _generate_verification_code()
    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        first_name=data.first_name,
        last_name=data.last_name,
        verification_code=code,
        verification_expires_at=utcnow() + timedelta(minutes=VERIFICATION_CODE_TTL_MINUTES),
    )
    session.add(user)
    await session.commit()
    print(f"[DEV] Verification code for {data.email}: {code}")
    return code


async def verify_email(session: AsyncSession, email: str, code: str) -> None:
    user = await session.scalar(select(User).where(User.email == email))
    if not user or user.verification_code != code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code")
    expires = user.verification_expires_at
    if expires is not None and ensure_aware(expires) < utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification code expired")
    user.is_verified = True
    user.verification_code = None
    user.verification_expires_at = None
    await session.commit()


async def authenticate(session: AsyncSession, email: str, password: str) -> User:
    user = await session.scalar(select(User).where(User.email == email))
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email not verified")
    return user


async def _persist_refresh_token(session: AsyncSession, user_id: int) -> str:
    token = create_refresh_token(user_id)
    session.add(
        RefreshToken(
            user_id=user_id,
            token=token,
            expires_at=utcnow() + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    return token


async def issue_tokens(session: AsyncSession, user: User) -> tuple[str, str]:
    access = create_access_token(user.id)
    refresh = await _persist_refresh_token(session, user.id)
    await session.commit()
    return access, refresh


async def rotate_refresh_token(session: AsyncSession, refresh_token: str) -> tuple[str, str]:

    decoded = decode_token(refresh_token)  # validates signature + JWT exp
    if decoded.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    row = await session.scalar(select(RefreshToken).where(RefreshToken.token == refresh_token))

    if not row or row.revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        
    if ensure_aware(row.expires_at) < utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    user = await session.get(User, row.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    row.revoked = True
    access = create_access_token(user.id)
    new_refresh = await _persist_refresh_token(session, user.id)
    await session.commit()
    return access, new_refresh
