"""In-process background cleanup.

Done with asyncio so the monolith needs no extra infra. In a horizontally scaled
deployment this would move to a Celery beat job (or a DB-level scheduler) so the sweep
runs once cluster-wide instead of once per process.
"""

import asyncio
from datetime import timedelta

from sqlalchemy import delete

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import utcnow
from app.modules.auth.models import RefreshToken
from app.modules.users.models import User


async def purge_unverified_users() -> int:
    # simplified version of user deletion without using celery. | Add celery "AT SCALE" 
    cutoff = utcnow() - timedelta(days=settings.unverified_user_ttl_days)
    async with SessionLocal() as session:
        result = await session.execute(
            delete(User).where(User.is_verified.is_(False), User.created_at < cutoff)
        )
        await session.commit()
        return result.rowcount or 0


async def purge_expired_refresh_tokens() -> int:
    async with SessionLocal() as session:
        result = await session.execute(
            delete(RefreshToken).where(RefreshToken.expires_at < utcnow())
        )
        await session.commit()
        return result.rowcount or 0


async def cleanup_loop() -> None:
    while True:
        try:
            removed_users = await purge_unverified_users()
            removed_tokens = await purge_expired_refresh_tokens()
            if removed_users or removed_tokens:
                print(
                    f"[CLEANUP] removed {removed_users} unverified user(s), "
                    f"{removed_tokens} expired refresh token(s)"
                )
        except Exception as exc:  # never let a transient DB error kill the loop
            print(f"[CLEANUP] error during sweep: {exc}")
        await asyncio.sleep(settings.cleanup_interval_seconds)
