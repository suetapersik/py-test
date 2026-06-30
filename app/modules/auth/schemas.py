"""Pydantic schemas for the auth module."""

from pydantic import BaseModel, EmailStr


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class VerifyRequest(BaseModel):
    email: EmailStr
    code: str


class RefreshRequest(BaseModel):
    refresh_token: str
