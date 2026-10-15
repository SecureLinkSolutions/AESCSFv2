from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    database_url: str
    valkey_url: str
    secret_key: str = Field(min_length=32)
    session_ttl_seconds: int = 8 * 60 * 60
    cookie_secure: bool = True
    base_path: str = "/app"

    # Failed-login throttling, per username and per client IP.
    login_max_failures: int = 5
    login_lockout_seconds: int = 15 * 60


@lru_cache
def get_settings() -> Settings:
    return Settings()
