# Secure Link Scanner Platform

Private, Tailscale-only platform for authorised, throttled external scanning of
Secure Link Solutions clients, plus reviewed Sigma and YARA rule drafting. The
full brief is the *Security Scanning Platform: Build Spec* (15 Oct 2026).

**Status: milestone M1 (skeleton).** Login works and the stack runs. There are no
clients, scopes, scans or rules yet.

## What M1 contains

| Piece | Where | Notes |
|---|---|---|
| Compose stack | `compose.yaml` | caddy, api, postgres, valkey |
| Reverse proxy | `caddy/Caddyfile` | `/` → `/app/`; `/app*` → api; everything else 404. TLS from Caddy's internal CA |
| API and UI | `api/app/` | FastAPI, server-rendered Jinja templates, htmx included locally |
| Auth | `api/app/auth.py`, `sessions.py` | Argon2id passwords, sessions held in Valkey, CSRF on every POST, lockout after repeated failed logins |
| Migrations | `api/migrations/` | Alembic; applied automatically when the api container starts |
| Staff accounts | `api/app/cli.py` | `create-user`, `set-password`, `disable-user`, `enable-user` |
| Tests | `tests/` | Auth flows, passwords, and a compose guard that fails if anything but Caddy publishes a port or Caddy binds to anything but `$TAILSCALE_IP` |
| Exposure check | `scripts/check-exposure.sh` | Run on the host after `up` |

### Network layout

```
 tailnet ──► $TAILSCALE_IP:443 ──► caddy ─(frontend, internal)─► api ─(backend, internal)─► postgres, valkey
```

- `edge`: caddy only. This is the only network with a published port.
- `frontend` and `backend` are `internal: true`, so the api, Postgres and Valkey
  have no outbound internet. The worker and intel services get their own egress
  network in M3 and M5.
- Postgres and Valkey never publish ports. Valkey requires a password.
- The api container runs as a non-root user, with a read-only root filesystem,
  all capabilities dropped and `no-new-privileges` set.

## Decisions taken for M1 (open decisions in the spec)

- **Frontend:** server-rendered with htmx. The htmx file (2.0.4, 0BSD licence)
  is stored in the repo, so pages load nothing from a CDN.
- **Queue:** Valkey is running, but the RQ-or-Celery choice is still open; it
  is made in M3. RQ is the leaning, since it is simpler.
- **Tailscale vs Headscale:** M1 doesn't depend on either. Caddy binds to
  whatever IP the host has on the tailnet.

## Quick start (lab)

```bash
cp .env.example .env        # fill in every value; generate secrets as noted
docker compose up -d --build
docker compose exec api python -m app.cli create-user <name>
./scripts/check-exposure.sh
```

Then browse to `https://$SITE_HOST/` from a device on the tailnet. The full host
setup, including Tailscale, UFW and trusting Caddy's root certificate, is in
[`docs/runbooks/m1-setup.md`](docs/runbooks/m1-setup.md).

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r api/requirements-dev.txt
pytest            # uses SQLite + fakeredis; no containers needed
ruff check . && ruff format --check .
```

## Layout

```
compose.yaml  caddy/  api/  worker/ (M3)  intel/ (M5)  rules/sigma  rules/yara  tests/  docs/runbooks/  scripts/
```
