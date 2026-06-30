# Users API

Test task to ORB IT. 

## Endpoints


- POST | `/auth/signup` | public | Register; returns dev verification code |
- POST | `/auth/login` | public | Authenticate, get access + refresh tokens |
- POST | `/auth/refresh` | public | Rotate refresh token, get a new pair |
- POST | `/auth/verify` | public | Verify email via code |
- GET | `/me` | authenticated | Current user's profile |
- GET | `/users` | admin | List users |
- GET | `/users/{id}` | admin | Get user by id |
- PATCH | `/users/{id}` | self or admin | Partial update |
- DELETE | `/users/{id}` | admin | Delete user |
- GET | `/health` | public | Liveness probe |

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
*production deployment should send the code via an email host / sms saas instead of logging it.*

## Background cleanup (auto-delete unverified users)

`app/tasks/cleanup.py` runs an in-process **asyncio** loop, started in the app lifespan:

- deletes users that never verified within `UNVERIFIED_USER_TTL_DAYS`,
- prunes expired refresh tokens.

At scale moving this to Celery.

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

Container itself running an alembic migration.

### Local (without Docker)

```bash
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

## Environment (`.env`)

- `DATABASE_URL` | yes | – | e.g. `postgresql+asyncpg://user:pass@db:5432/appdb` |
- `SECRET_KEY` | yes | – | JWT signing key |
- `ALGORITHM` | no | `HS256` | |
- `ACCESS_TOKEN_EXPIRE_MINUTES` | no | `15` | |
- `REFRESH_TOKEN_EXPIRE_DAYS` | no | `30` | |
- `UNVERIFIED_USER_TTL_DAYS` | no | `2` | cleanup threshold |
- `CLEANUP_INTERVAL_SECONDS` | no | `3600` | how often the sweep runs |
- `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | yes (compose) | – | used to build the Postgres container and `DATABASE_URL` |

## Error codes

- `400` invalid input or business rule (e.g. email taken, not verified, bad/expired code)
- `401` unauthenticated / invalid token
- `403` forbidden (role)
- `404` not found

## Admin role and verification

Getting into db with default data:
```bash
docker compose exec db psql -U testorbit -d appdb -c
```
Promoting to admin:
```bash
"UPDATE users SET role='admin' WHERE email='your@email.com';"
```
If you want to verify despite seeing "UPDATE 1":
```bash
"SELECT id, email, role, is_verified FROM users;"
```