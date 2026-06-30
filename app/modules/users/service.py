"""Data-access logic for users. HTTP concerns live in the router."""

from collections.abc import Sequence
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.users.models import User
from app.modules.users.schemas import UserUpdate


async def get_by_id(session: AsyncSession, user_id: int) -> Optional[User]:
    return await session.get(User, user_id)


async def get_by_email(session: AsyncSession, email: str) -> Optional[User]:
    return await session.scalar(select(User).where(User.email == email))


async def list_all(session: AsyncSession) -> Sequence[User]:
    result = await session.execute(select(User))
    return result.scalars().all()


async def apply_update(session: AsyncSession, user: User, data: UserUpdate) -> User:
    # exclude_unset => true PATCH semantics (only provided fields are touched).
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(user, field, value)
    await session.commit()
    await session.refresh(user)
    return user


async def delete(session: AsyncSession, user: User) -> None:
    await session.delete(user)
    await session.commit()
