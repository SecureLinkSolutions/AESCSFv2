"""Shared template setup for the server-rendered UI."""

from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi.templating import Jinja2Templates

from app.config import get_settings

APP_DIR = Path(__file__).parent


def local_zone() -> ZoneInfo:
    return ZoneInfo(get_settings().timezone)


def format_local(value: datetime | None, fmt: str = "%d %b %Y %H:%M") -> str:
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(local_zone()).strftime(fmt)


def parse_local(value: str) -> datetime:
    """Parse a <input type=datetime-local> value as local time and return it in UTC."""
    return datetime.fromisoformat(value).replace(tzinfo=local_zone()).astimezone(UTC)


def make_templates() -> Jinja2Templates:
    settings = get_settings()
    templates = Jinja2Templates(directory=APP_DIR / "templates")
    templates.env.globals["base"] = settings.base_path
    templates.env.globals["tz_name"] = settings.timezone
    templates.env.filters["localtime"] = format_local
    return templates
