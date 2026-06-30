# Users API
Users API tets task built with -> FastAPI and async SQLAlchemy:
- registration, 
- JWT authentication, 
- email verification, 
- role-based access,
- user management.

## Architecture
- Single entrypoint: `main.py` (modular monolith)
- Auth flows: `/auth/signup`, `/auth/login`, `/auth/refresh`, `/auth/verify`
- User management: `/me` (alias `/users/me`), `/users`, `/users/{id}`
- Database: async SQLAlchemy with asyncpg and PostgreSQL via Docker
- Background cleanup: in-process asyncio task purges unverified users past their TTL
- Config: environment variables loaded from `.env`

## Prerequisites
- Docker
- Docker Compose

## Run
```bash
docker compose up --build
```

Open API docs at `http://localhost:8000/docs`.

## Environment
Required `.env` values:
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_DB`
- `SECRET_KEY`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `REFRESH_TOKEN_EXPIRE_DAYS`
- `UNVERIFIED_USER_TTL_DAYS` (optional, default `2`)
- `CLEANUP_INTERVAL_SECONDS` (optional, default `3600`)

## Error codes
- `400` invalid input or business rule
- `401` unauthenticated
- `403` forbidden
- `404` not found

## Notes
- Unverified-user cleanup runs as an in-process asyncio loop started in the app lifespan
  (`cleanup_loop` → `purge_unverified_users`), deleting users that never verified within
  `UNVERIFIED_USER_TTL_DAYS`. This keeps the project single-process with no extra infra.
  In a horizontally scaled deployment this would move to a Celery beat job (or a DB-level
  scheduler) so the sweep runs once cluster-wide rather than once per process.
