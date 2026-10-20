from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.scope import Blocklist, Limits


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

    # Times shown in the UI and entered in forms. Stored as UTC.
    timezone: str = "Australia/Sydney"

    # Signed authorisation letters (PDF) are stored here, one folder per client.
    authorisation_dir: str = "/data/authorisations"
    max_authorisation_bytes: int = 10 * 1024 * 1024

    # Extra CIDRs that must never be scanned, comma separated (e.g. our own ranges).
    blocklist_extra: str = ""
    # Largest CIDR a single scope item may cover.
    min_cidr_prefix_v4: int = 24
    min_cidr_prefix_v6: int = 112

    verifier_poll_seconds: int = 5

    @property
    def blocklist(self) -> "Blocklist":
        return Blocklist.from_config(self.blocklist_extra)

    @property
    def scope_limits(self) -> "Limits":
        return Limits(self.min_cidr_prefix_v4, self.min_cidr_prefix_v6)


@lru_cache
def get_settings() -> Settings:
    return Settings()
