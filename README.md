# AESCSF v2 Evidence Tracker

A web application for organisations implementing and assessing against the **Australian Energy Sector Cyber Security Framework (AESCSF) Version 2**. Supports evidence recording, maturity tracking, remediation planning, gap registers, PDF reporting, and AEMO CSV export — deployable on-premises with Microsoft Entra ID (Azure AD) SSO and role-based access control.

![AESCSF Dashboard](https://github.com/SecureLinkSolutions/AESCSFv2/blob/main/Dashboard.png)

---

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Deployment](#deployment)
- [EntraID SSO Registration](#entraid-sso-registration)
- [RBAC — Roles and Access Control](#rbac--roles-and-access-control)
- [Database Schema](#database-schema)
- [Security Implementation](#security-implementation)
- [Local Development (no Docker)](#local-development-no-docker)
- [Disclaimer](#disclaimer)

---

## Features

| Feature | Description |
|---|---|
| Assessment tracking | 150+ AESCSF v2 practices across 11 domains with MIL-1/2/3 and anti-practice statuses |
| Save button per practice | Changes are buffered locally and written to the database only on explicit Save — preventing audit log spam from every keystroke |
| Evidence management | Evidence text, attachment links, owner, target dates, last reviewed |
| File attachments | Upload files (up to 20 MB each) against individual practices; stored in the SQLite-backed volume |
| Dashboard | Executive summary, domain maturity radar chart, completion and gap metrics |
| Remediation timeline | Chronological view of target dates with overdue indicators |
| Year-on-year comparison | Save named snapshots to the database; select any two to compare domain scores, status distribution, gap delta, and a full practice change register |
| Audit log | Immutable per-field change log — who changed what value on which practice and when; exportable as CSV; configurable automatic retention and admin purge |
| PDF report | Full assessment report with radar charts, domain summary, and gap register |
| AEMO CSV export | Practice status in the AEMO-required CSV template format |
| Gap register export | Filtered CSV of open gaps and remediation actions |
| JSON backup / restore | Full assessment import and export for backup or transfer |
| EntraID SSO | Microsoft Entra ID (Azure AD) authentication via oauth2-proxy — no JS auth libraries |
| RBAC | Admin (assessment master) and User (assigned domains only) roles |
| Sidebar navigation | Fixed 220px sidebar with per-role visibility; responsive drawer on mobile |
| Command palette | `Cmd+K` / `Ctrl+K` fuzzy search across practices, pages, and actions |
| Empty states | Contextual illustrated empty and error states throughout the UI |
| Branded login page | Custom `/login` landing page with Microsoft sign-in button |
| On-prem deployment | Docker Compose stack — Nginx + oauth2-proxy + Node.js API + SQLite, with Caddy for automatic TLS |

---

## Architecture

```
Internet
    │ HTTPS (443)
┌───▼──────────────────────────────────────────────────┐
│  Caddy  (host — automatic Let's Encrypt TLS)          │
│  Terminates TLS; reverse-proxies to localhost:8080    │
│  Adds HSTS, security headers, gzip/zstd compression  │
└───┬──────────────────────────────────────────────────┘
    │ HTTP (127.0.0.1:8080)
┌───▼──────────────────────────────────────────────────────────────┐
│                         Docker network                            │
│                                                                   │
│  Browser (SPA — vanilla JS, Chart.js)                             │
│  • No auth libraries — session cookie is HTTP-only                │
│  • All /api/* requests sent with same-origin cookie               │
│                                │                                  │
│  ┌─────────────────────────────▼──────────────────────────────┐  │
│  │              Nginx  (sole Docker entry point)               │  │
│  │  • Serves /login (branded login — no auth required)         │  │
│  │  • Validates every protected request via auth_request        │  │
│  │  • Unauthenticated → redirect to /login                     │  │
│  │  • Serves index.html, static assets, /config.js             │  │
│  │  • Strips client-supplied X-Auth-Request-* headers           │  │
│  │  • Proxies /api/* to the Node.js backend                    │  │
│  │  • Proxies /oauth2/* to oauth2-proxy (OIDC flow)            │  │
│  └────────┬───────────────────────────────────────────────────┘  │
│           │ auth_request subrequest       │ /api/* proxy          │
│  ┌────────▼──────────────────┐  ┌────────▼───────────────────┐   │
│  │  oauth2-proxy  (internal) │  │  Node.js / Express  (api)  │   │
│  │  • Handles OIDC flow      │  │  • Reads identity from     │   │
│  │  • Returns 202/401        │  │    X-Auth-Request-* headers │   │
│  │  • Sets X-Auth-Request-*  │  │  • RBAC: admin / user      │   │
│  │  • No host port exposed   │  │  • No host port exposed    │   │
│  └───────────────────────────┘  └────────┬───────────────────┘   │
│                                           │                        │
│  ┌────────────────────────────────────────▼───────────────────┐   │
│  │                SQLite  (named Docker volume)                │   │
│  │  tables: assessments, users, assignments, snapshots,       │   │
│  │          audit_log, files                                  │   │
│  └────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                               │
               ┌───────────────▼───────────────┐
               │      Microsoft Entra ID        │
               │  (OIDC token issuance only)    │
               └───────────────────────────────┘
```

### Request flow

1. **Unauthenticated user** hits Caddy → nginx → auth_request to oauth2-proxy → 401 → redirect to `/login`
2. **Login page** (`/login`) is served by nginx without an auth check
3. **Sign in** — user clicks "Sign in with Microsoft" → oauth2-proxy → Microsoft Entra ID OIDC → `/oauth2/callback` → HTTP-only session cookie set → redirect to app
4. **Authenticated request** — nginx sends auth_request → 202 with `X-Auth-Request-*` headers → nginx strips client-supplied values, injects proxy-validated identity into API request
5. **Sign out** — `/oauth2/sign_out` → cookie cleared → redirect to `/login`

### File structure

```
AESCSFv2/
├── index.html              Single-page application (HTML + CSS + JS)
├── config.js               Local dev config; overwritten at container start
│                           by nginx/entrypoint.sh
├── docker-compose.yml      On-prem stack: nginx + oauth2-proxy + api
├── .env.example            Configuration reference (copy to .env)
├── .gitignore
├── .dockerignore
│
├── deploy/
│   ├── setup.sh            One-command Linode/Ubuntu provisioner (run once as root)
│   └── update.sh           Zero-downtime updater — pull, rebuild, rolling restart
│
├── nginx/
│   ├── Dockerfile          nginx:alpine image
│   ├── nginx.conf          auth_request wiring, SPA routing, /api proxy, CSP headers
│   ├── rate-limit.conf     nginx rate-limit zones
│   ├── login.html          Branded sign-in landing page
│   └── entrypoint.sh       Generates /config.js from env vars at startup
│
└── server/
    ├── server.js           Express API — auth, RBAC, assessment CRUD, audit,
    │                       files, rate limiting, HTTP logging, graceful shutdown
    ├── package.json        Dependencies: express, better-sqlite3, helmet, cors,
    │                       multer, morgan, express-rate-limit
    └── Dockerfile          node:24-alpine image, non-root user (aescsf)
```

---

## Deployment

### Option A — Automated (Ubuntu 22.04 / 24.04 on Linode or similar VPS)

The setup script provisions a complete production server in one step: Docker, Caddy (automatic HTTPS), UFW firewall, app user, repo clone, `.env` generation, daily SQLite backups, and unattended security upgrades.

**Prerequisites before running:**

1. A fresh Ubuntu 22.04 or 24.04 VPS with root SSH access
2. A domain name with an **A record pointing to your server's IP** and DNS resolving correctly (verify with `dig yourdomain.com +short`)
3. A Microsoft Entra ID app registration — see [EntraID SSO Registration](#entraid-sso-registration)

**Run as root:**

```bash
curl -fsSL https://raw.githubusercontent.com/SecureLinkSolutions/AESCSFv2/main/deploy/setup.sh -o setup.sh
bash setup.sh
```

> Note: Download the script first rather than piping directly to `bash` — the script prompts for interactive input which `curl | bash` prevents.

The script will ask for:

| Prompt | Example |
|---|---|
| Domain | `aescsf.yourcompany.com` |
| Azure Client ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| Azure Tenant ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| Azure Client Secret | `your-secret-value` |
| Admin Object ID(s) | leave blank to make first login user admin |
| Allowed email domains | `yourcompany.com` or `*` for any tenant |
| Audit log retention days | `365` |

After the script completes, add the redirect URI to your Azure app registration (the script prints it):

```
https://aescsf.yourcompany.com/oauth2/callback
```

Then browse to `https://aescsf.yourcompany.com` — Caddy obtains a TLS certificate automatically on the first request.

**Updating to a new version:**

```bash
bash /opt/aescsf/deploy/update.sh
```

This takes a pre-update backup, pulls the latest code, rebuilds images, and rolling-restarts services with minimal downtime.

---

### Option B — Manual Docker Compose

For self-managed servers or non-Ubuntu environments.

**Prerequisites:**

- Docker and Docker Compose installed
- A reverse proxy (nginx, Caddy, Traefik) handling TLS termination, or internal network only
- A Microsoft Entra ID app registration

**1. Clone and configure**

```bash
git clone https://github.com/SecureLinkSolutions/AESCSFv2.git
cd AESCSFv2
cp .env.example .env
```

Edit `.env`:

```env
# ── Entra ID ──────────────────────────────────────────────────
AESCSF_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AESCSF_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AESCSF_CLIENT_SECRET=your-client-secret-value

# ── oauth2-proxy ──────────────────────────────────────────────
OAUTH2_PROXY_REDIRECT_URL=https://aescsf.yourcompany.com/oauth2/callback
OAUTH2_PROXY_OIDC_ISSUER_URL=https://login.microsoftonline.com/<TENANT_ID>/v2.0

# Generate with: openssl rand -hex 16
OAUTH2_PROXY_COOKIE_SECRET=replace-with-32-char-hex-string

OAUTH2_PROXY_COOKIE_SECURE=true
OAUTH2_PROXY_EMAIL_DOMAINS=yourcompany.com
OAUTH2_PROXY_WHITELIST_DOMAINS=aescsf.yourcompany.com,login.microsoftonline.com

# ── RBAC ──────────────────────────────────────────────────────
# Optional: leave blank to make first sign-in user the admin
# AESCSF_ADMIN_OIDS=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# ── App ───────────────────────────────────────────────────────
AESCSF_STORAGE_MODE=api
AESCSF_AUDIT_RETENTION_DAYS=365
ALLOWED_ORIGIN=https://aescsf.yourcompany.com

# ── Network ───────────────────────────────────────────────────
HOST_BIND=127.0.0.1   # bind to localhost only; your TLS proxy sits in front
HOST_PORT=8080
```

**2. Build and start**

```bash
docker compose up -d --build
```

**3. Verify**

```bash
curl http://127.0.0.1:8080/api/health
# → {"status":"ok","db":"ok"}
```

**4. First sign-in = first admin**

The first user to complete the Microsoft sign-in is automatically assigned the **Admin** role.

### Viewing logs

```bash
docker compose logs -f api      # API access log + app messages
docker compose logs -f nginx    # nginx access and error log
docker compose logs -f          # all services
```

### Backups

The automated setup installs a daily cron job at 02:00 UTC that copies the SQLite database to `/var/backups/aescsf/` and retains 30 days of snapshots. Run manually at any time:

```bash
/usr/local/bin/aescsf-backup
```

---

## EntraID SSO Registration

1. Sign in to [portal.azure.com](https://portal.azure.com)
2. Go to **Microsoft Entra ID → App registrations → + New registration**
   - Name: `AESCSF v2 Evidence Tracker`
   - Supported account types: **Accounts in this organizational directory only**
   - Redirect URI: **Web** → `https://aescsf.yourcompany.com/oauth2/callback`
3. Note the **Application (client) ID** → `AESCSF_CLIENT_ID`
4. Note the **Directory (tenant) ID** → `AESCSF_TENANT_ID`
5. Go to **Certificates & secrets → + New client secret**
   - Set an expiry and click **Add**
   - Copy the **Value** immediately (shown only once) → `AESCSF_CLIENT_SECRET`

> No API permissions or scopes beyond the defaults are required. oauth2-proxy uses standard OpenID Connect scopes (`openid email profile`).

---

## RBAC — Roles and Access Control

### Roles

| Role | Assessment view | Can edit | Admin tab |
|---|---|---|---|
| **Admin** (Assessment Master) | All 11 domains | All domains | Yes |
| **User** | Assigned domains only | Assigned domains only | No |

### How it works

1. Every user who completes Microsoft sign-in is automatically registered in the database.
2. The **first** user to sign in is made Admin (or pin admins via `AESCSF_ADMIN_OIDS`).
3. The Admin opens the **Admin** page and assigns domains to each user.
4. Users log in and see only their assigned domains in the Assessment and Dashboard views.
5. Users fill in evidence, status, owners, and notes and click **Save** on each practice card.
6. The Admin can click **Load Merged View** to see a consolidated assessment combining all users' contributions.

### Admin panel

The **Admin** page provides:

- **User cards** — name, email, role badge, role toggle (promote/demote), domain assignment checkboxes
- **Save assignments** — updates the user's domain scope immediately
- **Load Merged View** — read-only combined assessment from all users

All role and domain assignment changes are written to the audit log.

### API endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | None | Liveness probe — returns `{"status":"ok","db":"ok"}` |
| `GET` | `/api/me` | User | Current user's profile, role, assigned domains |
| `GET` | `/api/assessment` | User | Load own assessment data |
| `PUT` | `/api/assessment` | User | Save own assessment (restricted to assigned domains for non-admins) |
| `GET` | `/api/admin/users` | Admin | List all registered users with roles and assignments |
| `PUT` | `/api/admin/users/:oid/role` | Admin | Set a user's role (`admin` or `user`) |
| `PUT` | `/api/admin/users/:oid/assignments` | Admin | Set a user's domain list |
| `GET` | `/api/admin/assessment/merged` | Admin | Merged assessment from all users |
| `GET` | `/api/snapshots` | User | List saved snapshots |
| `POST` | `/api/snapshots` | User | Save a named snapshot |
| `GET` | `/api/snapshots/:id` | User | Load a specific snapshot |
| `DELETE` | `/api/snapshots/:id` | User | Delete a snapshot (own only) |
| `GET` | `/api/audit` | User | Paginated audit log (admins see all; users see own) |
| `GET` | `/api/audit/export` | User | Full audit log as CSV (rate-limited: 10/15 min) |
| `GET` | `/api/audit/practice/:id` | User | Audit history for a specific practice |
| `DELETE` | `/api/audit/purge` | Admin | Purge entries older than `AESCSF_AUDIT_RETENTION_DAYS` |
| `POST` | `/api/files/:practiceId` | User | Upload a file attachment |
| `GET` | `/api/files/:practiceId` | User | List file attachments for a practice |
| `GET` | `/api/files/:id/download` | User | Download a file |
| `DELETE` | `/api/files/:id` | User | Delete a file (own only; admins can delete any) |

---

## Database Schema

All data is stored in a single SQLite file (`aescsf.db`) in the `aescsf_data` Docker named volume. WAL mode and foreign-key constraints are enabled. All SQL uses prepared statements.

| Table | Purpose |
|---|---|
| `assessments` | One row per user — full assessment JSON. Keyed by `(user_oid, tenant_id)`. |
| `users` | One row per authenticated user — OID, tenant, username, display name, role, timestamps. |
| `assignments` | Many-to-many mapping of users to AESCSF domains. |
| `snapshots` | Named point-in-time copies of a user's assessment JSON for year-on-year comparison. |
| `audit_log` | One row per field change — who, what practice, which field, old value, new value, when. Purged automatically on schedule. |
| `files` | Metadata for file attachments. File content stored on disk in `DATA_DIR/files/`. |

---

## Security Implementation

### Network layer

- **Caddy** terminates TLS on the host and proxies to the Docker nginx on `127.0.0.1:8080` only — the Docker port is never exposed on a public interface.
- **Nginx** is the sole Docker-network entry point. oauth2-proxy and the API have no host ports (`expose:` not `ports:`).
- **CORS** — `ALLOWED_ORIGIN` must be set explicitly; no wildcard default in production.
- **UFW** — SSH, HTTP (port 80, for Let's Encrypt renewals), and HTTPS (port 443) only. All other ports blocked.

### Authentication

The stack uses the **nginx `auth_request` module**:

1. nginx issues an internal subrequest to `oauth2-proxy /oauth2/auth` for every request.
2. oauth2-proxy returns **202** (authenticated) with `X-Auth-Request-*` identity headers, or **401**.
3. On **401**, nginx redirects to `/login` — no application content is served to unauthenticated clients.
4. On **202**, nginx **strips any client-supplied** `X-Auth-Request-*` headers (preventing identity spoofing) and re-injects the proxy-validated values into the upstream API request.

The session is an **HTTP-only, SameSite=Lax** cookie (`_aescsf_session`) — inaccessible to browser JavaScript.

The API reads identity exclusively from nginx-injected headers. Token signature validation is performed by oauth2-proxy; no auth libraries (MSAL.js, jsonwebtoken, jwks-rsa) exist in the browser or API.

> **Entra ID note:** Work accounts store email in `preferred_username`, not the standard `email` claim. oauth2-proxy is configured with `OAUTH2_PROXY_OIDC_EMAIL_CLAIM=preferred_username`.

### Authorisation (RBAC)

- Role is stored server-side in SQLite and checked on every request — it cannot be elevated by the client.
- Non-admin users saving practices outside their assigned domains have those entries stripped silently by the backend.
- Admin-only endpoints return `403` for non-admin sessions unconditionally.

### Rate limiting

**Nginx** (`nginx/rate-limit.conf`):
- `oauth2_login` zone: 10 requests/minute per IP, burst of 5

**Express** (`express-rate-limit`):
- General: 300 requests per 15 minutes per IP
- Export: 10 requests per 15 minutes per IP

### HTTP security headers

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (set by Caddy) |
| `X-Frame-Options` | `DENY` (set by Caddy) |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

### Backend hardening

- `helmet` applied with default protections.
- Body size limits: nginx 25 MB outer gate → multer 20 MB per file → `express.json` 4 MB for JSON payloads.
- SQLite WAL mode and foreign-key constraints enabled.
- All SQL uses prepared statements.
- API container runs as non-root user (`aescsf`).
- Graceful shutdown on `SIGTERM`/`SIGINT` with 10-second forced timeout.

### Runtime configuration

No secrets are baked into images. `AESCSF_CLIENT_SECRET` and `OAUTH2_PROXY_COOKIE_SECRET` live only in `.env` and are injected at runtime via Docker Compose environment variables.

---

## Local Development (no Docker)

Open `index.html` directly in a browser for a fully offline experience. Set `storageMode: "local"` in `config.js` — data is stored in `localStorage` with no backend required.

To run the API locally without SSO:

```bash
cd server
npm install
AESCSF_SSO_ENABLED=false DATA_DIR=./data node server.js
```

Set `storageMode: "api"` in `config.js`. With `AESCSF_SSO_ENABLED=false` the server assigns a static `anonymous` user with no identity headers required.

---

## Disclaimer

This tool is provided for assessment and evidence tracking purposes only and does not guarantee compliance with AESCSF or any regulatory requirement. Users are responsible for validating assessments, evidence, and compliance outcomes.

AI was used in creating this tool.
