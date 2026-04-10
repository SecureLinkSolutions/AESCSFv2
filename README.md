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
| Save button per practice | Changes to evidence, notes, and owner fields are buffered locally and written to the database only on explicit Save — preventing audit log spam from every keystroke |
| Evidence management | Evidence text, attachment links, owner, target dates, last reviewed |
| File attachments | Upload files (up to 25 MB each) against individual practices; stored in the SQLite-backed volume |
| Dashboard | Executive summary, domain maturity radar chart, completion and gap metrics |
| Remediation timeline | Chronological view of target dates with overdue indicators |
| Year-on-year comparison | Save named snapshots to the database; select any two to compare domain scores, status distribution, gap delta, and a full practice change register |
| Audit log | Immutable per-field change log — who changed what value on which practice and when; exportable as CSV |
| PDF report | Full assessment report with radar charts, domain summary, and gap register |
| AEMO CSV export | Practice status in the AEMO-required CSV template format |
| Gap register export | Filtered CSV of open gaps and remediation actions |
| JSON backup / restore | Full assessment import and export for backup or transfer |
| EntraID SSO | Microsoft Entra ID (Azure AD) authentication via oauth2-proxy — no JS auth libraries |
| RBAC | Admin (assessment master) and User (assigned domains only) roles |
| Branded login page | Custom `/login` landing page with Microsoft sign-in button; first thing unauthenticated users see |
| On-prem deployment | Docker Compose stack — Nginx + oauth2-proxy + Node.js API + SQLite |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         Internal Network                          │
│                                                                   │
│  Browser                                                          │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │  index.html  (SPA — vanilla JS, Chart.js)                  │   │
│  │                                                            │   │
│  │  • No auth libraries — session cookie is HTTP-only         │   │
│  │  • All /api/* requests sent with same-origin cookie        │   │
│  └────────────────────────────┬───────────────────────────────┘   │
│                               │ HTTP (HOST_BIND:HOST_PORT)         │
│  ┌────────────────────────────▼───────────────────────────────┐   │
│  │              Nginx  (sole public entry point)               │   │
│  │                                                            │   │
│  │  • Serves /login (branded login page — no auth required)   │   │
│  │  • Validates every protected request via auth_request      │   │
│  │    subrequest to oauth2-proxy                              │   │
│  │  • Unauthenticated requests → redirect to /login           │   │
│  │  • Serves index.html, static assets, /config.js            │   │
│  │  • Strips any client-supplied X-Auth-Request-* headers,    │   │
│  │    then re-injects proxy-validated identity headers         │   │
│  │  • Proxies /api/* to the Node.js backend                   │   │
│  │  • Proxies /oauth2/* to oauth2-proxy (OIDC flow)           │   │
│  └────────┬───────────────────────────────────────────────────┘   │
│           │ auth_request subrequest          │ /api/* proxy        │
│  ┌────────▼──────────────────┐   ┌───────────▼───────────────┐   │
│  │  oauth2-proxy  (internal) │   │  Node.js / Express  (api) │   │
│  │                           │   │                           │   │
│  │  • Handles /oauth2/* OIDC │   │  • Reads identity from    │   │
│  │    flow (sign_in,         │   │    X-Auth-Request-*       │   │
│  │    callback, sign_out)    │   │    headers set by nginx    │   │
│  │  • /oauth2/auth returns   │   │  • Decodes access token   │   │
│  │    202 (authenticated) or │   │    for OID + display name │   │
│  │    401 (not authenticated)│   │  • RBAC: admin / user     │   │
│  │  • Sets X-Auth-Request-*  │   │  • Assessment, snapshot,  │   │
│  │    response headers       │   │    audit, file endpoints  │   │
│  │  • No host port exposed   │   │  • No host port exposed   │   │
│  └───────────────────────────┘   └───────────┬───────────────┘   │
│                                               │                    │
│  ┌────────────────────────────────────────────▼───────────────┐   │
│  │                 SQLite  (named Docker volume)               │   │
│  │  tables: assessments, users, assignments, snapshots,       │   │
│  │          audit_log, files                                  │   │
│  └────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                               │
               ┌───────────────▼───────────────┐
               │      Microsoft Entra ID        │
               │  (OIDC token issuance only;    │
               │   signature verification done  │
               │   inside oauth2-proxy)         │
               └───────────────────────────────┘
```

### Request flow

1. **Unauthenticated user** hits nginx → nginx sends auth_request to oauth2-proxy `/oauth2/auth` → oauth2-proxy returns 401 → nginx redirects to `/login`
2. **Login page** (`/login`) is served by nginx without an auth check — the user sees the branded page
3. **Sign in** — user clicks "Sign in with Microsoft" → `/oauth2/sign_in` → oauth2-proxy → Microsoft Entra ID OIDC → `/oauth2/callback` → oauth2-proxy sets HTTP-only session cookie → redirects to original URL
4. **Authenticated request** — nginx sends auth_request → oauth2-proxy returns 202 with `X-Auth-Request-*` headers → nginx captures headers via `auth_request_set`, strips any client-supplied values, injects proxy-validated identity into the API request
5. **Sign out** — user clicks Sign out → `/oauth2/sign_out` → oauth2-proxy clears the session cookie → redirects to `/login`

### File structure

```
AESCSFv2/
├── index.html              Single-page application (HTML + CSS + JS)
├── config.js               Local dev config; overwritten at container start
│                           by nginx/entrypoint.sh
├── docker-compose.yml      On-prem stack: nginx + oauth2-proxy + api
├── .env.example            Configuration reference (copy to .env)
│
├── nginx/
│   ├── Dockerfile          nginx:alpine image
│   ├── nginx.conf          auth_request wiring, SPA routing, /api proxy
│   ├── login.html          Branded sign-in landing page
│   └── entrypoint.sh       Generates /config.js from env vars at startup
│
└── server/
    ├── server.js           Express API — auth, RBAC, assessment CRUD, audit, files
    ├── package.json        Dependencies: express, better-sqlite3, helmet, cors, multer
    └── Dockerfile          node:20-alpine image
```

---

## Deployment

### Prerequisites

- Docker and Docker Compose installed on the host machine
- The host must be reachable only from your internal network (bind to an internal NIC — see `HOST_BIND`)
- A Microsoft Entra ID (Azure AD) app registration (see [EntraID SSO Registration](#entraid-sso-registration))

### Steps

**1. Clone and configure**

```bash
git clone https://github.com/SecureLinkSolutions/AESCSFv2.git
cd AESCSFv2
cp .env.example .env
```

Edit `.env` and fill in every value:

```env
# ── Entra ID app registration ────────────────────────────────
AESCSF_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AESCSF_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AESCSF_CLIENT_SECRET=your-client-secret-value-here

# ── oauth2-proxy ─────────────────────────────────────────────
# Must exactly match the Redirect URI in your app registration
OAUTH2_PROXY_REDIRECT_URL=http://192.168.1.10/oauth2/callback

# Replace the GUID with your actual tenant ID
OAUTH2_PROXY_OIDC_ISSUER_URL=https://login.microsoftonline.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/v2.0

# Generate with: python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
OAUTH2_PROXY_COOKIE_SECRET=replace-with-generated-secret

OAUTH2_PROXY_COOKIE_SECURE=false     # set to true when using HTTPS
OAUTH2_PROXY_EMAIL_DOMAINS=*         # or restrict to yourcompany.com

# Allowed redirect hosts after sign-in / sign-out.
# Add your server's IP or hostname here (comma-separated, no protocol).
OAUTH2_PROXY_WHITELIST_DOMAINS=192.168.1.10

# ── RBAC ─────────────────────────────────────────────────────
# Optional: pin admins by Entra ID Object ID (comma-separated).
# If blank, the first user to sign in becomes admin automatically.
# AESCSF_ADMIN_OIDS=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# ── Storage and network ───────────────────────────────────────
AESCSF_STORAGE_MODE=api
HOST_BIND=192.168.1.10               # your server's internal NIC IP
HOST_PORT=80
ALLOWED_ORIGIN=http://192.168.1.10
```

> Run `ip addr` (Linux) or `ipconfig` (Windows) to find your server's internal IP.

**2. Build and start**

```bash
docker compose up -d --build
```

**3. Verify**

```bash
curl http://192.168.1.10/api/health
# → {"status":"ok","sso":true,...}
```

Browse to `http://192.168.1.10` — you will land on the branded **AESCSF v2 Sign In** page. Click **Sign in with Microsoft** to complete the Entra ID OIDC flow and be redirected into the application.

**4. First sign-in = first admin**

The first user to sign in is automatically assigned the **Admin** role. They can then assign roles and domains to subsequent users via the **Admin** tab.

---

## EntraID SSO Registration

1. Sign in to [portal.azure.com](https://portal.azure.com)
2. Go to **Microsoft Entra ID → App registrations → + New registration**
   - Name: `AESCSF v2 Evidence Tracker`
   - Supported account types: **Accounts in this organizational directory only**
   - Redirect URI: **Web** → `http://<YOUR-SERVER-IP>/oauth2/callback`
     (e.g. `http://192.168.1.10/oauth2/callback`)
3. Note the **Application (client) ID** → `AESCSF_CLIENT_ID`
4. Note the **Directory (tenant) ID** → `AESCSF_TENANT_ID`
5. Go to **Certificates & secrets → + New client secret**
   - Set an expiry and click **Add**
   - Copy the **Value** immediately (shown only once) → `AESCSF_CLIENT_SECRET`

> No API scope or additional API permissions are required. oauth2-proxy uses standard OpenID Connect scopes (`openid email profile`).

---

## RBAC — Roles and Access Control

### Roles

| Role | Assessment view | Can edit | Admin tab |
|---|---|---|---|
| **Admin** (Assessment Master) | All 11 domains | All domains | Yes |
| **User** | Assigned domains only | Assigned domains only | No |

### How it works

1. Every user who completes the Microsoft sign-in is automatically registered in the database.
2. The **first** user to sign in is made Admin (or you can pin admins via `AESCSF_ADMIN_OIDS`).
3. The Admin opens the **Admin** tab and assigns domains to each user — e.g. the network team gets `ARCHITECTURE` and `ACCESS`, the risk team gets `RISK` and `THREAT`.
4. Users log in and see only their assigned domains in the Assessment and Dashboard views.
5. Users fill in evidence, status, owners, and remediation notes for their practices and click **Save** on each practice card to persist changes.
6. The Admin can click **Load Merged View** to overlay a consolidated assessment that combines every user's contributions. All users are included regardless of whether they have domain assignments.

### Admin panel

The **Admin** tab provides:

- **User cards** — name, email, role badge, role toggle (promote/demote), domain assignment checkboxes
- **Save assignments** — updates the user's domain scope immediately
- **Load Merged View** — loads a read-only combined assessment from all users; a banner indicates merged mode with a **Restore my view** button

### API endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | None | Liveness probe |
| `GET` | `/api/me` | User | Current user's profile, role, assigned domains |
| `GET` | `/api/assessment` | User | Load own assessment data |
| `PUT` | `/api/assessment` | User | Save own assessment (restricted to assigned domains for non-admins) |
| `GET` | `/api/admin/users` | Admin | List all registered users with roles and assignments |
| `PUT` | `/api/admin/users/:oid/role` | Admin | Set a user's role (`admin` or `user`) |
| `PUT` | `/api/admin/users/:oid/assignments` | Admin | Set a user's domain list |
| `GET` | `/api/admin/assessment/merged` | Admin | Merged assessment from all users |
| `GET` | `/api/snapshots` | User | List the current user's saved snapshots |
| `POST` | `/api/snapshots` | User | Save a named snapshot of the current assessment |
| `GET` | `/api/snapshots/:id` | User | Load full data for a specific snapshot |
| `DELETE` | `/api/snapshots/:id` | User | Delete a snapshot (own snapshots only) |
| `GET` | `/api/audit` | User | Paginated audit log (admins see all users; users see own) |
| `GET` | `/api/audit/export` | User | Full audit log as CSV download |
| `GET` | `/api/audit/practice/:id` | User | Audit history for a specific practice |
| `POST` | `/api/files/:practiceId` | User | Upload a file attachment for a practice |
| `GET` | `/api/files/:practiceId` | User | List file attachments for a practice |
| `GET` | `/api/files/:id/download` | User | Download a specific file |
| `DELETE` | `/api/files/:id` | User | Delete a file (own files only; admins can delete any) |

---

## Database Schema

All data is stored in a single SQLite file (`aescsf.db`) inside the `aescsf_data` Docker named volume. SQLite WAL mode and foreign-key constraints are enabled. All SQL uses prepared statements — no string interpolation.

| Table | Purpose |
|---|---|
| `assessments` | One row per user — full assessment data stored as a JSON blob (`data` column). Keyed by `(user_oid, tenant_id)`. Updated on every explicit Save. |
| `users` | One row per authenticated user — OID, tenant, username, display name, role (`admin`/`user`), created and last-seen timestamps. |
| `assignments` | Many-to-many mapping of users to AESCSF domains. Controls which domains each User role can view and edit. |
| `snapshots` | Named point-in-time copies of a user's assessment JSON. Used for year-on-year comparison. |
| `audit_log` | One row per field change — records who (`user_oid`, `username`, `display_name`), what practice (`practice_id`), which field, the old value, the new value, and when. Written on every explicit Save. There is no automatic retention or purge policy; rows accumulate indefinitely. |
| `files` | Metadata for uploaded file attachments — filename, stored name, MIME type, size, upload time. File content is stored on disk in `DATA_DIR`. |

---

## Security Implementation

### Network layer

- **Docker port binding** — the host port is bound to `HOST_BIND` (your internal NIC IP), not `0.0.0.0`. The application socket is never opened on internet-facing interfaces.
- **Nginx as sole public entry point** — oauth2-proxy and the API container have no host ports exposed (`expose:` not `ports:`). All external traffic enters through nginx only.
- **CORS** — `ALLOWED_ORIGIN` must be explicitly set; there is no wildcard `*` default in production.

### Authentication

The stack uses the **nginx `auth_request` module** to enforce authentication:

1. nginx receives every request and issues an internal subrequest to `oauth2-proxy /oauth2/auth`.
2. oauth2-proxy validates the session cookie and returns **202** (authenticated) or **401** (not authenticated). It also sets `X-Auth-Request-User`, `X-Auth-Request-Email`, and `X-Auth-Request-Access-Token` response headers on 202.
3. On **401**, nginx redirects the browser to `/login` (the branded sign-in page) — no application content is ever served to unauthenticated clients.
4. On **202**, nginx captures the identity headers via `auth_request_set`, **strips any client-supplied** `X-Auth-Request-*` headers (preventing identity spoofing), and re-injects the proxy-validated values into the upstream API request.

The session is maintained via an **HTTP-only, SameSite=Lax** cookie (`_aescsf_session`). The cookie is inaccessible to browser JavaScript and is forwarded automatically on same-origin requests.

The API reads identity exclusively from the nginx-injected `X-Auth-Request-*` headers — it decodes (but does not re-verify) the access token to extract the Entra ID Object ID (`oid`) and display name. Token signature validation is performed by oauth2-proxy; no auth libraries (MSAL.js, jsonwebtoken, jwks-rsa) are present in the browser or API code.

> **Entra ID note:** Work accounts in most Entra ID tenants store the user's email address in `preferred_username`, not the standard OIDC `email` claim. oauth2-proxy is configured with `OAUTH2_PROXY_OIDC_EMAIL_CLAIM=preferred_username` to handle this. The API reads `X-Auth-Request-User` (always set by the Azure provider) as the primary identity, with `X-Auth-Request-Email` and `X-Auth-Request-Preferred-Username` as fallbacks.

### Sign-out

Clicking **Sign out** navigates to `/oauth2/sign_out`, which clears the `_aescsf_session` cookie and redirects to `/login`. The user is returned to the branded sign-in page. The underlying Azure SSO session is not terminated — this matches standard SaaS behaviour (clearing the application session without forcing a global Microsoft logout).

### Authorisation (RBAC)

- Role (`admin` / `user`) is stored server-side in SQLite and checked on every request — it cannot be elevated by the client.
- Non-admin users who attempt to save practices outside their assigned domains have those entries **silently stripped** by the backend before persistence.
- Admin-only endpoints (`/api/admin/*`) return `403` for any non-admin session regardless of what the client sends.

### HTTP security headers (Nginx)

| Header | Value |
|---|---|
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin` |

### Backend hardening (Express / Helmet)

- `helmet` is applied with default protections.
- `express.json` body size is capped at `4 MB`; file uploads are capped at `25 MB` per file via `multer`.
- SQLite WAL mode and foreign-key constraints are enabled.
- All SQL interactions use prepared statements — no string interpolation.
- The API container is not exposed on the host network; it is only reachable through nginx on the internal Docker network.

### Runtime configuration

- No secrets are baked into container images. `AESCSF_CLIENT_SECRET` and `OAUTH2_PROXY_COOKIE_SECRET` live only in the `.env` file and are injected at runtime via Docker Compose environment variables.
- Nginx generates `/config.js` from environment variables at container start via `nginx/entrypoint.sh`. The file contains only non-sensitive runtime settings (storage mode, API path, tenant ID).

---

## Local Development (no Docker)

Open `index.html` directly in a browser for a fully offline experience. Set `storageMode: "local"` in `config.js` — data is stored in browser `localStorage` with no backend required.

To run the API locally without SSO:

```bash
cd server
npm install
AESCSF_SSO_ENABLED=false DATA_DIR=./data node server.js
```

Set `storageMode: "api"` in `config.js` and ensure the API is running on port 3000. With `AESCSF_SSO_ENABLED=false` the server accepts requests without requiring any identity headers and assigns a static `anonymous` user.

---

## Disclaimer

This tool is provided for assessment and evidence tracking purposes only and does not guarantee compliance with AESCSF or any regulatory requirement. Users are responsible for validating assessments, evidence, and compliance outcomes.

AI was used in creating this tool.
