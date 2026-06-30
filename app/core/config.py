from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    database_url: str
    secret_key: str

    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30

    unverified_user_ttl_days: int = 2
    cleanup_interval_seconds: int = 3600


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
