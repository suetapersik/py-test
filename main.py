import asyncio
import random
import secrets
import string
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql.functions import now

import os
from dotenv import load_dotenv

load_dotenv()

# Settings from .env
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
# Unverified accounts older than this are purged by the background cleanup task.
UNVERIFIED_USER_TTL_DAYS = int(os.getenv("UNVERIFIED_USER_TTL_DAYS", "2"))
# How often the in-process cleanup loop runs (hourly is plenty for a 2-day TTL).
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "3600"))

# async DB setup
engine = create_async_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db():
    async with SessionLocal() as session:
        yield session


class Base(DeclarativeBase):
    pass


# Models
class UserRole(str):
    USER = "user"
    ADMIN = "admin"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    first_name: Mapped[str | None] = mapped_column(String(120))
    last_name: Mapped[str | None] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(20), default=UserRole.USER)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_code: Mapped[str | None] = mapped_column(String(6), nullable=True)
    verification_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), onupdate=now(), nullable=True)

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=now())

    user: Mapped[User] = relationship("User", back_populates="refresh_tokens")


# Auth helpers
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware(value: datetime) -> datetime:
    # SQLite stores naive datetimes; treat them as UTC so comparisons never raise.
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def hash_password(password: str) -> str:
    # bcrypt only uses the first 72 bytes; truncate to avoid hashing errors on long passwords
    return pwd_context.hash(password[:72])


def verify_password(plain_password: str, hashed_password: str) -> bool:
    # truncate before verify so it matches the stored hash created from password[:72]
    return pwd_context.verify(plain_password[:72], hashed_password)


def create_access_token(user_id: int) -> str:
    expire = _utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # jti keeps tokens unique even when two are minted in the same second.
    payload = {"sub": str(user_id), "exp": expire, "type": "access", "jti": secrets.token_hex(8)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user_id: int) -> str:
    expire = _utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {"sub": str(user_id), "exp": expire, "type": "refresh", "jti": secrets.token_hex(8)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc


# Schemas
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class UserRead(BaseModel):
    id: int
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    role: str
    is_verified: bool
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class MessageResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    email: str
    password: str


class VerifyRequest(BaseModel):
    email: EmailStr
    code: str


class RefreshRequest(BaseModel):
    refresh_token: str


# Auth dependencies (async)
async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    authorization = request.headers.get("authorization")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    payload = decode_token(token)
    # Reject refresh tokens used as access tokens.
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    user_id = int(payload["sub"])
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return user


async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# Delete unverified users after TTL=2
async def purge_unverified_users() -> int:
    cutoff = _utcnow() - timedelta(days=UNVERIFIED_USER_TTL_DAYS)
    async with SessionLocal() as session:
        result = await session.execute(
            delete(User).where(User.is_verified.is_(False), User.created_at < cutoff)
        )
        await session.commit()
        return result.rowcount or 0


async def cleanup_loop() -> None:
    """Background loop that periodically purges stale unverified users."""
    while True:
        try:
            removed = await purge_unverified_users()
            if removed:
                print(f"[CLEANUP] Removed {removed} unverified user(s) older than {UNVERIFIED_USER_TTL_DAYS}d")
        except Exception as exc:  # never let a transient DB error kill the loop
            print(f"[CLEANUP] Error during purge: {exc}")
        await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_tables()
    cleanup_task = asyncio.create_task(cleanup_loop())
    try:
        yield
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Users API", lifespan=lifespan)


@app.get("/health", summary="Health check", description="Simple health check endpoint for Docker.")
async def health() -> dict:
    return {"status": "ok"}


@app.post(
    "/auth/signup",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Creates a new user account and returns a dev verification code.",
)
async def signup(payload: UserCreate, session: AsyncSession = Depends(get_db)) -> MessageResponse:
    existing = await session.scalar(select(User).where(User.email == payload.email))
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        first_name=payload.first_name,
        last_name=payload.last_name,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    code = "".join(random.choices(string.digits, k=6))
    user.verification_code = code
    user.verification_expires_at = _utcnow() + timedelta(minutes=15)
    await session.commit()
    print(f"[DEV] Verification code for {payload.email}: {code}")
    return MessageResponse(message=f"Registered. Dev verification code: {code}")


@app.post(
    "/auth/login",
    response_model=TokenResponse,
    summary="Sign in",
    description="Authenticate user and return access/refresh tokens. Requires verified account.",
)
async def login(payload: LoginRequest, session: AsyncSession = Depends(get_db)) -> TokenResponse:
    user = await session.scalar(select(User).where(User.email == payload.email))
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email not verified")

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    session.add(
        RefreshToken(
            user_id=user.id,
            token=refresh_token,
            expires_at=_utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        )
    )
    await session.commit()
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@app.post(
    "/auth/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Exchange a valid refresh token for a new access token.",
)
async def refresh(payload: RefreshRequest, session: AsyncSession = Depends(get_db)) -> TokenResponse:
    # decode_token validates the signature and the JWT "exp" claim.
    decoded = decode_token(payload.refresh_token)
    if decoded.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    token_row = await session.scalar(select(RefreshToken).where(RefreshToken.token == payload.refresh_token))
    if not token_row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    # Authoritative server-side expiry check (covers tokens revoked by shortening the TTL).
    if _ensure_aware(token_row.expires_at) < _utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    user = await session.get(User, token_row.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return TokenResponse(access_token=create_access_token(user.id), refresh_token=payload.refresh_token)


@app.post(
    "/auth/verify",
    response_model=MessageResponse,
    summary="Verify email",
    description="Confirm account via code.",
)
async def verify(payload: VerifyRequest, session: AsyncSession = Depends(get_db)) -> MessageResponse:
    if not payload.email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required")
    user = await session.scalar(select(User).where(User.email == payload.email))
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code")
    if user.verification_code != payload.code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code")
    expires = user.verification_expires_at
    if expires is not None and _ensure_aware(expires) < _utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification code expired")
    user.is_verified = True
    user.verification_code = None
    user.verification_expires_at = None
    await session.commit()
    return MessageResponse(message="Email verified")


@app.get(
    "/me",
    response_model=UserRead,
    summary="Get current user",
    description="Return the authenticated user's profile.",
)
@app.get(
    "/users/me",
    response_model=UserRead,
    summary="Get current user",
    description="Return the authenticated user's profile.",
)
async def get_me(user: User = Depends(get_current_user)) -> UserRead:
    return UserRead(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        role=user.role,
        is_verified=user.is_verified,
        created_at=user.created_at,
    )


@app.get(
    "/users",
    response_model=list[UserRead],
    summary="List users",
    description="List all users. Admin only.",
)
async def list_users(_: User = Depends(require_admin), session: AsyncSession = Depends(get_db)) -> list[UserRead]:
    result = await session.execute(select(User))
    users = result.scalars().all()
    return [
        UserRead(
            id=u.id,
            email=u.email,
            first_name=u.first_name,
            last_name=u.last_name,
            role=u.role,
            is_verified=u.is_verified,
            created_at=u.created_at,
        )
        for u in users
    ]


@app.get(
    "/users/{user_id}",
    response_model=UserRead,
    summary="Get user by id",
    description="Return user by id. Admin only.",
)
async def get_user(user_id: int, _: User = Depends(require_admin), session: AsyncSession = Depends(get_db)) -> UserRead:
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserRead(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        role=user.role,
        is_verified=user.is_verified,
        created_at=user.created_at,
    )


@app.patch(
    "/users/{user_id}",
    response_model=UserRead,
    summary="Update user",
    description="Partially update user data. Allowed for the user themselves or an admin.",
)
async def update_user(user_id: int, payload: dict, current_user: User = Depends(get_current_user), session: AsyncSession = Depends(get_db)) -> UserRead:
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    for field in ("first_name", "last_name"):
        if field in payload:
            setattr(user, field, payload[field])
    await session.commit()
    await session.refresh(user)
    return UserRead(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        role=user.role,
        is_verified=user.is_verified,
        created_at=user.created_at,
    )


@app.delete(
    "/users/{user_id}",
    response_model=MessageResponse,
    summary="Delete user",
    description="Delete user by id. Admin only.",
)
async def delete_user(user_id: int, _: User = Depends(require_admin), session: AsyncSession = Depends(get_db)) -> MessageResponse:
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await session.delete(user)
    await session.commit()
    return MessageResponse(message="User deleted")
