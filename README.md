# Users API
Test task to ORB IT. 

## Endpoints

- POST  `/auth/signup`  public & Register; returns dev verification code 
- POST  `/auth/login`  public & Authenticate, get access + refresh tokens 
- POST  `/auth/refresh`  public & Rotate refresh token, get a new pair 
- POST  `/auth/verify`  public & Verify email via code 
- GET  `/me`  authenticated & Current user's profile 
- GET  `/users`  admin only & List users 
- GET  `/users/{id}`  admin only & Get user by id 
- PATCH | `/users/{id}`  self or admin & Partial update 
- DELETE | `/users/{id}`  admin only & Delete user 
- GET  `/health`  public & Liveness probe 

## Authentication

- **JWT** access + refresh tokens (`python-jose`, HS256). Each token carries `type`
  (`access`/`refresh`) and a random `jti` for uniqueness.
- `get_current_user` accepts only `type=access` tokens, so a refresh token cannot be
  used as an access token.
- **Refresh-token rotation:** refresh tokens are persisted. `/auth/refresh` validates the
  token (signature, expiry, DB row, not-revoked), then **revokes the old token and issues
  a new pair** — a leaked/replayed refresh token cannot be reused.

## Verification

after signup -> 6-digit code is generated. POST `/auth/verify` confirms the account. 
*production deployment should send the code via an email host / sms saas instead of logging it.*

## Background cleanup (auto-delete unverified users)

`app/tasks/cleanup.py` runs in asyncio loop, started in the app lifespan:
- deletes users which wasn't verified within `UNVERIFIED_USER_TTL_DAYS`,
- prunes expired refresh tokens.

At scale moving this to Celery.

## Database & migrations

- async sqlAlchemy 2.0 with `asyncpg` against postgreSQL inside of Docker.
- schema is managed by alembic (`migrations/`, async `env.py`). The app doesn't
  auto-create tables & migrations are the only source of truth.

```bash
alembic upgrade head
alembic revision --autogenerate -m "message"
```

## Run

```bash
docker compose up --build
```

Container itself runns an alembic migration.

### Local (without Docker)

```bash
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

## Environment (`.env`)

- `DATABASE_URL` 
- `SECRET_KEY` 
- `ALGORITHM` 
- `ACCESS_TOKEN_EXPIRE_MINUTES` 
- `REFRESH_TOKEN_EXPIRE_DAYS` 
- `UNVERIFIED_USER_TTL_DAYS` 
- `CLEANUP_INTERVAL_SECONDS` 
- `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` 

## Error codes

- `400` invalid input or business rule (e.g. email taken, not verified, bad/expired code)
- `401` unauthenticated / invalid token
- `403` forbidden (role)
- `404` not found

## Admin role and verification

Getting into db with default data:
```bash
docker compose exec db psql -U appuser -d appdb -c
```
Promoting to admin:
```bash
"UPDATE users SET role='admin' WHERE email='your@email.com';"
```
If you want to verify despite seeing "UPDATE 1":
```bash
"SELECT id, email, role, is_verified FROM users;"
```