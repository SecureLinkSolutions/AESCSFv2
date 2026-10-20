"""Staff account management. Run inside the api container:

docker compose exec api python -m app.cli create-user alice
docker compose exec api python -m app.cli set-password alice
docker compose exec api python -m app.cli disable-user alice
"""

import argparse
import getpass
import sys

from sqlalchemy import select

from app.db import get_sessionmaker
from app.models import User
from app.passwords import hash_password
from app.services import audit


def _prompt_password() -> str:
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Confirm password: "):
        sys.exit("Passwords do not match")
    return password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("create-user", "set-password", "disable-user", "enable-user"):
        sub.add_parser(name).add_argument("username")
    args = parser.parse_args(argv)

    with get_sessionmaker()() as db:
        user = db.scalar(select(User).where(User.username == args.username))

        if args.command == "create-user":
            if user is not None:
                sys.exit(f"User {args.username!r} already exists")
            try:
                db.add(
                    User(username=args.username, password_hash=hash_password(_prompt_password()))
                )
            except ValueError as exc:
                sys.exit(str(exc))
        else:
            if user is None:
                sys.exit(f"No such user {args.username!r}")
            if args.command == "set-password":
                try:
                    user.password_hash = hash_password(_prompt_password())
                except ValueError as exc:
                    sys.exit(str(exc))
            else:
                user.is_active = args.command == "enable-user"
        audit(db, "cli", f"user.{args.command}", f"user:{args.username}")
        db.commit()

    print(f"{args.command}: {args.username} done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
