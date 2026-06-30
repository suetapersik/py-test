"""Application factory, lifespan and router wiring.

Schema is owned by Alembic (`alembic upgrade head`), not create_all, so this module
does not create tables. The lifespan only manages the background cleanup task.
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

# Importing the models registers them on the SQLAlchemy mapper (both must be loaded
# for the User <-> RefreshToken relationship to resolve).
from app.modules.auth import models as _auth_models  # noqa: F401
from app.modules.auth.router import router as auth_router
from app.modules.users import models as _user_models  # noqa: F401
from app.modules.users.router import router as users_router
from app.tasks.cleanup import cleanup_loop


@asynccontextmanager
async def lifespan(app: FastAPI):
    cleanup_task = asyncio.create_task(cleanup_loop())
    try:
        yield
    finally:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


def create_app() -> FastAPI:
    app = FastAPI(
        title="Users API",
        description="User management: registration, JWT auth, verification, roles.",
        version="1.0.0",
        lifespan=lifespan,
    )

    @app.get("/health", tags=["system"], summary="Health check", description="Liveness probe for Docker.")
    async def health() -> dict:
        return {"status": "ok"}

    app.include_router(auth_router)
    app.include_router(users_router)
    return app


app = create_app()
