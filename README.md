# Users API

User-management service built with **FastAPI** and **async SQLAlchemy**:
registration, JWT authentication, email verification, role-based access, and user management.

Designed as a **modular monolith**: one deployable process, but organized into
self-contained feature modules with a shared core, so it can grow (or later be split
into services) without a rewrite.

## Project structure

```
.
├── app/
│   ├── main.py              # App factory, lifespan (background tasks), /health, router wiring
│   ├── core/                # Cross-cutting concerns shared by all modules
│   │   ├── config.py        # Settings (pydantic-settings, reads .env)
│   │   ├── database.py      # Async engine, session factory, Base, get_db dependency
│   │   ├── security.py      # Password hashing, JWT create/decode, datetime helpers
│   │   └── schemas.py       # Shared response schemas (MessageResponse)
│   ├── modules/             # Feature modules (the "modular" part of the monolith)
│   │   ├── auth/            # Signup, login, refresh (rotation), verify
│   │   │   ├── models.py        # RefreshToken
│   │   │   ├── schemas.py       # Token/login/verify/refresh DTOs
│   │   │   ├── service.py       # Business logic (no FastAPI in the data flow)
│   │   │   ├── dependencies.py  # get_current_user / require_admin (HTTPBearer)
│   │   │   └── router.py        # /auth/* endpoints
│   │   └── users/           # User CRUD
│   │       ├── models.py        # User + UserRole
│   │       ├── schemas.py       # UserCreate / UserUpdate / UserRead
│   │       ├── service.py       # Data-access logic
│   │       └── router.py        # /me, /users, /users/{id}
│   └── tasks/
│       └── cleanup.py       # Background asyncio sweep (unverified users, expired tokens)
├── migrations/              # Alembic (async env) + versioned migrations
├── main.py                  # Thin shim re-exporting app.main:app (backwards compat)
├── Dockerfile
├── docker-compose.yml
├── alembic.ini
└── requirements.txt
```

**Module layout convention** — each feature module owns its `models / schemas / service /
router` (and `dependencies` where relevant). Routers handle HTTP; services hold business
logic; `core` holds everything cross-cutting. To add a feature, drop in a new module under
`app/modules/` and include its router in `app/main.py`.

## Endpoints

| Method | Path | Access | Description |
|--------|------|--------|-------------|
| POST | `/auth/signup` | public | Register; returns dev verification code |
| POST | `/auth/login` | public | Authenticate, get access + refresh tokens |
| POST | `/auth/refresh` | public | Rotate refresh token, get a new pair |
| POST | `/auth/verify` | public | Verify email via code |
| GET | `/me` | authenticated | Current user's profile |
| GET | `/users` | admin | List users |
| GET | `/users/{id}` | admin | Get user by id |
| PATCH | `/users/{id}` | self or admin | Partial update |
| DELETE | `/users/{id}` | admin | Delete user |
| GET | `/health` | public | Liveness probe |

Interactive docs (Swagger UI) at `http://localhost:8000/docs`, with an **Authorize**
button for testing protected endpoints (paste an access token).

## Authentication

- **JWT** access + refresh tokens (`python-jose`, HS256). Each token carries `type`
  (`access`/`refresh`) and a random `jti` for uniqueness.
- `get_current_user` accepts only `type=access` tokens, so a refresh token cannot be
  used as an access token.
- **Refresh-token rotation:** refresh tokens are persisted. `/auth/refresh` validates the
  token (signature, expiry, DB row, not-revoked), then **revokes the old token and issues
  a new pair** — a leaked/replayed refresh token cannot be reused.

## Verification

After signup a 6-digit code is generated and (in dev) printed to the console. `POST
/auth/verify` confirms the account. Codes expire after 15 minutes.
*A production deployment would send the code via an email/SMS provider instead of logging it.*

## Background cleanup (auto-delete unverified users)

`app/tasks/cleanup.py` runs an in-process **asyncio** loop, started in the app lifespan:

- deletes users that never verified within `UNVERIFIED_USER_TTL_DAYS` (default **2 days**),
- prunes expired refresh tokens.

This keeps the project single-process with no extra infrastructure. **At scale** this would
move to a **Celery beat** job (or a DB-level scheduler) so the sweep runs once cluster-wide
rather than once per process — the cleanup functions are already factored to be called from
either place.

## Database & migrations

- Async SQLAlchemy 2.0 with `asyncpg` against **PostgreSQL** (Docker).
- Schema is managed by **Alembic** (`migrations/`, async `env.py`). The app does **not**
  auto-create tables; migrations are the single source of truth.

```bash
alembic upgrade head            # apply migrations
alembic revision --autogenerate -m "message"   # create a new migration after model changes
```

## Run

```bash
docker compose up --build
```

The app container runs `alembic upgrade head` and then starts Uvicorn. Open
`http://localhost:8000/docs`.

### Local (without Docker)

```bash
pip install -r requirements.txt
# point DATABASE_URL at a reachable Postgres, then:
alembic upgrade head
uvicorn app.main:app --reload
```

## Environment (`.env`)

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `DATABASE_URL` | yes | – | e.g. `postgresql+asyncpg://user:pass@db:5432/appdb` |
| `SECRET_KEY` | yes | – | JWT signing key |
| `ALGORITHM` | no | `HS256` | |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | no | `15` | |
| `REFRESH_TOKEN_EXPIRE_DAYS` | no | `30` | |
| `UNVERIFIED_USER_TTL_DAYS` | no | `2` | cleanup threshold |
| `CLEANUP_INTERVAL_SECONDS` | no | `3600` | how often the sweep runs |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | yes (compose) | – | used to build the Postgres container and `DATABASE_URL` |

## Error codes

- `400` invalid input or business rule (e.g. email taken, not verified, bad/expired code)
- `401` unauthenticated / invalid token
- `403` forbidden (role)
- `404` not found

## Notes & deliberate simplifications

- Verification codes are logged, not emailed (dev). Swap in an email/SMS provider for prod.
- Cleanup runs in-process via asyncio; see the section above for the Celery-at-scale path.
- `bcrypt` is pinned to `4.0.1` because `passlib==1.7.4` is incompatible with bcrypt ≥ 4.1.
