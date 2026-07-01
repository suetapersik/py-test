"""Unit tests for the pure helpers in app.core.security."""

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    ensure_aware,
    hash_password,
    verify_password,
)


def test_password_hash_roundtrip():
    hashed = hash_password("secret123")
    assert hashed != "secret123"
    assert verify_password("secret123", hashed)
    assert not verify_password("wrong", hashed)


def test_password_longer_than_72_bytes_does_not_crash():
    long_password = "a" * 200
    hashed = hash_password(long_password)
    assert verify_password(long_password, hashed)


def test_access_token_carries_sub_and_type():
    payload = decode_token(create_access_token(42))
    assert payload["sub"] == "42"
    assert payload["type"] == "access"


def test_refresh_token_type():
    assert decode_token(create_refresh_token(1))["type"] == "refresh"


def test_tokens_are_unique_via_jti():
    # Two tokens for the same user minted back-to-back must differ.
    assert create_access_token(1) != create_access_token(1)


def test_decode_invalid_token_raises_401():
    with pytest.raises(HTTPException) as exc:
        decode_token("not-a-jwt")
    assert exc.value.status_code == 401


def test_ensure_aware_makes_naive_utc_and_leaves_aware():
    assert ensure_aware(datetime(2020, 1, 1)).tzinfo is not None
    aware = datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert ensure_aware(aware) == aware
