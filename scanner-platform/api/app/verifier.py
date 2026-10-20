"""Verifier service: picks up domain verification requests and checks them.

Runs as its own container (same image as the api) because it needs outbound DNS
and HTTPS, which the api container deliberately doesn't have. It polls Postgres
rather than using a queue, so it doesn't pre-empt the RQ-or-Celery decision (M3).

    python -m app.verifier          # loop forever
    python -m app.verifier --once   # process what's pending, then exit
"""

import argparse
import logging
import time
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_sessionmaker
from app.models import ScopeItem
from app.services import record_verification
from app.verify import VerifyResult, verify_domain

log = logging.getLogger("app.verifier")

Verifier = Callable[[str, str], VerifyResult]


def process_pending(db: Session, check: Verifier, limit: int = 20) -> int:
    """Verify up to `limit` requested domain items. Returns how many were processed."""
    items = db.scalars(
        select(ScopeItem)
        .where(
            ScopeItem.verify_requested_at.is_not(None),
            ScopeItem.removed_at.is_(None),
            ScopeItem.type == "domain",
        )
        .order_by(ScopeItem.verify_requested_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    ).all()
    for item in items:
        try:
            result = check(item.value, item.verify_record_value)
        except Exception as exc:  # a crash in one check must not stop the others
            log.exception("verification crashed for %s", item.value)
            result = VerifyResult(False, None, f"verifier error: {exc.__class__.__name__}")
        log.info("verify %s ok=%s %s", item.value, result.ok, result.detail)
        record_verification(db, item, result.ok, result.method, result.detail)
    return len(items)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.verifier")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    settings = get_settings()
    blocklist = settings.blocklist

    def check(domain: str, expected: str) -> VerifyResult:
        return verify_domain(domain, expected, blocklist)

    log.info("verifier started")
    while True:
        with get_sessionmaker()() as db:
            processed = process_pending(db, check)
        if args.once:
            return 0
        if not processed:
            time.sleep(settings.verifier_poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
