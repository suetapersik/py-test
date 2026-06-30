# Users API
Users API tets task built with -> FastAPI and async SQLAlchemy:
- registration, 
- JWT authentication, 
- email verification, 
- role-based access,
- user management.

## Architecture
- Single entrypoint: `main.py`
- Auth flows: `/auth/signup`, `/auth/login`, `/auth/refresh`, `/auth/verify`
- User management: `/users/me`, `/users`, `/users/{id}`
- Database: async SQLAlchemy with asyncpg and PostgreSQL via Docker
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

## Error codes
- `400` invalid input or business rule
- `401` unauthenticated
- `403` forbidden
- `404` not found

## Notes
- Unverified-user cleanup is described here instead of implemented with Celery/Redis for this test task.
