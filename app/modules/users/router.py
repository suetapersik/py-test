"""User management endpoints: /me, /users, /users/{id}."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.schemas import MessageResponse
from app.modules.auth.dependencies import get_current_user, require_admin
from app.modules.users import service
from app.modules.users.models import User, UserRole
from app.modules.users.schemas import UserRead, UserUpdate

router = APIRouter(tags=["users"])


@router.get(
    "/me",
    response_model=UserRead,
    summary="Get current user",
    description="Return the authenticated user's profile.",
)
@router.get("/users/me", response_model=UserRead, include_in_schema=False)
async def get_me(user: User = Depends(get_current_user)) -> User:
    return user


@router.get(
    "/users",
    response_model=list[UserRead],
    summary="List users",
    description="List all users. Admin only.",
)
async def list_users(
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> list[User]:
    return list(await service.list_all(session))


@router.get(
    "/users/{user_id}",
    response_model=UserRead,
    summary="Get user by id",
    description="Return a user by id. Admin only.",
)
async def get_user(
    user_id: int,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> User:
    user = await service.get_by_id(session, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.patch(
    "/users/{user_id}",
    response_model=UserRead,
    summary="Update user",
    description="Partially update a user. Allowed for the user themselves or an admin.",
)
async def update_user(
    user_id: int,
    payload: UserUpdate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> User:
    user = await service.get_by_id(session, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return await service.apply_update(session, user, payload)


@router.delete(
    "/users/{user_id}",
    response_model=MessageResponse,
    summary="Delete user",
    description="Delete a user by id. Admin only.",
)
async def delete_user(
    user_id: int,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> MessageResponse:
    user = await service.get_by_id(session, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await service.delete(session, user)
    return MessageResponse(message="User deleted")
