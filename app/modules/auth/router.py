from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.schemas import MessageResponse
from app.modules.auth import service
from app.modules.auth.schemas import LoginRequest, RefreshRequest, TokenResponse, VerifyRequest
from app.modules.users.schemas import UserCreate

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/signup",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Create a new (unverified) account and return a dev verification code.",
)
async def signup(payload: UserCreate, session: AsyncSession = Depends(get_db)) -> MessageResponse:
    code = await service.register_user(session, payload)
    return MessageResponse(message=f"Registered. Dev verification code: {code}")


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Sign in",
    description="Authenticate a verified user and return access/refresh tokens.",
)
async def login(payload: LoginRequest, session: AsyncSession = Depends(get_db)) -> TokenResponse:
    user = await service.authenticate(session, payload.email, payload.password)
    access, refresh = await service.issue_tokens(session, user)
    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh tokens",
    description="Exchange a valid refresh token for a new pair. The old token is revoked (rotation).",
)
async def refresh(payload: RefreshRequest, session: AsyncSession = Depends(get_db)) -> TokenResponse:
    access, new_refresh = await service.rotate_refresh_token(session, payload.refresh_token)
    return TokenResponse(access_token=access, refresh_token=new_refresh)


@router.post(
    "/verify",
    response_model=MessageResponse,
    summary="Verify email",
    description="Confirm an account using the verification code.",
)
async def verify(payload: VerifyRequest, session: AsyncSession = Depends(get_db)) -> MessageResponse:
    await service.verify_email(session, payload.email, payload.code)
    return MessageResponse(message="Email verified")
