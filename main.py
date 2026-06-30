"""Backwards-compatible entrypoint.

The application now lives in the `app` package (modular monolith). This shim keeps
`uvicorn main:app` working; prefer `uvicorn app.main:app` going forward.
"""

from app.main import app

__all__ = ["app"]
