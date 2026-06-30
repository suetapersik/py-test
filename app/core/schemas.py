"""Schemas shared across modules."""

from pydantic import BaseModel


class MessageResponse(BaseModel):
    message: str
