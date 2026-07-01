"""Shared test fixtures.

Tests run against an ephemeral SQLite database. The env vars are set BEFORE the
app is imported so app.core.database builds its engine against the test DB.
"""

import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_app.db"
os.environ["SECRET_KEY"] = "test-secret-key"

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.core.database import Base, SessionLocal, engine
from app.core.security import create_access_token, hash_password
from app.main import app
from app.modules.users.models import User, UserRole


@pytest_asyncio.fixture
async def db():
    """Fresh schema per test for full isolation."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


@pytest_asyncio.fixture
async def client(db):
    # ASGITransport does not run the lifespan, so the background cleanup loop stays off.
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


@pytest_asyncio.fixture
async def make_user(db):
    """Factory that inserts a user directly (defaults to a verified regular user)."""

    async def _make(
        email: str = "user@example.com",
        password: str = "password123",
        role: str = UserRole.USER,
        is_verified: bool = True,
    ) -> User:
        async with SessionLocal() as session:
            user = User(
                email=email,
                hashed_password=hash_password(password),
                role=role,
                is_verified=is_verified,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            return user

    return _make


@pytest.fixture
def auth_header():
    """Build an Authorization header with a valid access token for a user id."""

    def _header(user_id: int) -> dict:
        return {"Authorization": f"Bearer {create_access_token(user_id)}"}

    return _header
