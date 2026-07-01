"""Tests for the background cleanup logic (spec item 4: auto-delete unverified users)."""

from datetime import timedelta

from sqlalchemy import select

from app.core.database import SessionLocal
from app.core.security import hash_password, utcnow
from app.modules.auth.models import RefreshToken
from app.modules.users.models import User
from app.tasks.cleanup import purge_expired_refresh_tokens, purge_unverified_users


async def _add_user(email: str, is_verified: bool, created_days_ago: int) -> int:
    async with SessionLocal() as session:
        user = User(email=email, hashed_password=hash_password("x"), is_verified=is_verified)
        session.add(user)
        await session.commit()
        await session.refresh(user)
        user.created_at = utcnow() - timedelta(days=created_days_ago)
        await session.commit()
        return user.id


async def test_purge_removes_only_stale_unverified_users(db):
    await _add_user("stale@b.com", is_verified=False, created_days_ago=5)
    await _add_user("recent@b.com", is_verified=False, created_days_ago=0)
    await _add_user("verified@b.com", is_verified=True, created_days_ago=5)

    removed = await purge_unverified_users()
    assert removed == 1

    async with SessionLocal() as session:
        emails = set((await session.execute(select(User.email))).scalars().all())
    assert "stale@b.com" not in emails
    assert {"recent@b.com", "verified@b.com"} <= emails


async def test_purge_expired_refresh_tokens(db):
    user_id = await _add_user("tok@b.com", is_verified=True, created_days_ago=0)
    async with SessionLocal() as session:
        session.add(RefreshToken(user_id=user_id, token="expired", expires_at=utcnow() - timedelta(days=1)))
        session.add(RefreshToken(user_id=user_id, token="valid", expires_at=utcnow() + timedelta(days=1)))
        await session.commit()

    removed = await purge_expired_refresh_tokens()
    assert removed == 1
