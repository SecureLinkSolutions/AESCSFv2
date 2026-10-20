# Secure Link Scanner Platform

Private, Tailscale-only platform for authorised, throttled external scanning of
Secure Link Solutions clients, plus reviewed Sigma and YARA rule drafting. The
full brief is the *Security Scanning Platform: Build Spec* (15 Oct 2026).

**Status: M1 (skeleton) and M2 (scope and authorisation) are done.** Staff can
record clients, upload signed authorisation letters, add and verify scope, and
review the audit log. Nothing scans yet; that's M3.

## What M2 adds

| Piece | Where | Notes |
|---|---|---|
| Blocklist and scope rules | `api/app/scope.py` | Pure functions that the M3 worker will call before every tool and on every DNS answer. Refuses RFC1918, loopback, link-local and cloud metadata, CGNAT/Tailscale, multicast, reserved, documentation and benchmarking ranges, unique-local IPv6, IPv4 hidden inside IPv6 (mapped, NAT64, 6to4, Teredo), anything else not globally routable, and any extra CIDRs in `BLOCKLIST_EXTRA` |
| Clients | UI `/app/clients` | Name and contact. `dojo_product_id` is left empty until M4 |
| Authorisations | client page | Signed PDF (checked to be a PDF, max 10 MB, stored by SHA-256), signed by, validity window, the scanner source IP named in the letter. Can be revoked |
| Scope items | client page | Domain (covers its subdomains), IP, or CIDR (/24 or smaller by default). No wildcards, and no internal-only names (`.local`, `.internal`, `.ts.net`, ...). Overlaps are refused, both within a client and across clients |
| Verification | `api/app/verify.py`, `verifier.py` | Domains: a DNS TXT record or the `/.well-known/securelink-verify.txt` file, checked by the `verifier` container. IPs and CIDRs: a person confirms they're listed in the signed letter |
| Audit log | UI `/app/audit` | Every change, login and verification is logged in the same transaction as the change. A Postgres trigger refuses UPDATE, DELETE and TRUNCATE |
| What the worker may scan | `services.scannable_scope()` | Verified, not removed, under a live (started, unexpired, unrevoked) authorisation |

Domain verification instructions (shown per item in the UI):

```
_securelink-verify.<domain>  TXT  "securelink-verify=<token>"
# or
https://<domain>/.well-known/securelink-verify.txt  containing  securelink-verify=<token>
```

The file check resolves the domain itself, refuses blocked addresses, connects to
the address it checked (so a DNS change mid-check can't redirect it), and never
follows redirects. A failed re-check removes an earlier verification.

## What M1 contains

| Piece | Where | Notes |
|---|---|---|
| Compose stack | `compose.yaml` | caddy, api, verifier (M2), postgres, valkey |
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
  have no outbound internet.
- `egress`: outbound internet, only for services that need it. In M2 that's the
  `verifier` alone; the worker and intel services join it in M3 and M5.
- Postgres and Valkey never publish ports. Valkey requires a password.
- The api container runs as a non-root user, with a read-only root filesystem,
  all capabilities dropped and `no-new-privileges` set.

## Decisions taken for M1 (open decisions in the spec)

- **Frontend:** server-rendered with htmx. The htmx file (2.0.4, 0BSD licence)
  is stored in the repo, so pages load nothing from a CDN.
- **Queue:** Valkey is running, but the RQ-or-Celery choice is still open; it
  is made in M3. RQ is the leaning, since it is simpler. The M2 verifier polls
  Postgres, so it doesn't depend on that choice.
- **Tailscale vs Headscale:** M1 doesn't depend on either. Caddy binds to
  whatever IP the host has on the tailnet.

## Decisions taken for M2

- **A domain covers its subdomains.** Subdomains that subfinder finds under a
  verified domain are in scope. Their IP addresses only have to pass the
  blocklist, because sites on CDNs and shared hosting resolve to addresses the
  client doesn't own.
- **IPs and CIDRs are attested by a person**, not proven technically. A staff
  member confirms each one is listed in the signed letter, and the audit entry
  records who, plus the letter's SHA-256.
- **One client per target.** A domain or address can't be in scope for two
  clients at once.
- **Times** are entered and shown in `TIMEZONE` (default Australia/Sydney) and
  stored as UTC.
- **Per-job re-checks** of verification happen in the M3 worker, before each job.

## Quick start (lab)

```bash
cp .env.example .env        # fill in every value; generate secrets as noted
docker compose up -d --build
docker compose exec api python -m app.cli create-user <name>
./scripts/check-exposure.sh
```

Then browse to `https://$SITE_HOST/` from a device on the tailnet. The full host
setup, including Tailscale, UFW and trusting Caddy's root certificate, is in
[`docs/runbooks/setup.md`](docs/runbooks/setup.md).

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
