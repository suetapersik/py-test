"""User ORM model and role constants."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, false
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql.functions import now

from app.core.database import Base


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
    role: Mapped[str] = mapped_column(String(20), nullable=False, server_default=UserRole.USER)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())
    verification_code: Mapped[str | None] = mapped_column(String(6), nullable=True)
    verification_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), onupdate=now(), nullable=True)

    # Defined with a string target so users does not import auth (one-way dependency).
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(  # noqa: F821
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )
