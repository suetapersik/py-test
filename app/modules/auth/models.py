"""Refresh-token ORM model (persisted so tokens can be revoked/rotated)."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, false
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql.functions import now

from app.core.database import Base
# Import User so both classes are registered on the mapper before configure.
from app.modules.users.models import User


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=now())

    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")
