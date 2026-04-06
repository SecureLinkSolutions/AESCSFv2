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
- [Security Implementation](#security-implementation)
- [Local Development (no Docker)](#local-development-no-docker)
- [Disclaimer](#disclaimer)

---

## Features

| Feature | Description |
|---|---|
| Assessment tracking | 150+ AESCSF v2 practices across 11 domains with MIL-1/2/3 and anti-practice statuses |
| Evidence management | Evidence text, attachment links, owner, target dates, last reviewed |
| Dashboard | Executive summary, domain maturity radar chart, completion and gap metrics |
| Remediation timeline | Chronological view of target dates with overdue indicators |
| Year-on-year comparison | Save named snapshots to the database; select any two to compare domain scores, status distribution, gap delta, and a full practice change register |
| PDF report | Full assessment report with radar charts, domain summary, and gap register |
| AEMO CSV export | Practice status in the AEMO-required CSV template format |
| Gap register export | Filtered CSV of open gaps and remediation actions |
| JSON backup / restore | Full assessment import and export for backup or transfer |
| EntraID SSO | Microsoft Entra ID (Azure AD) authentication via oauth2-proxy — no JS auth libraries |
| RBAC | Admin (assessment master) and User (assigned domains only) roles |
| On-prem deployment | Docker Compose stack — oauth2-proxy + Nginx + Node.js API + SQLite |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Internal Network                       │
│                                                              │
│  Browser                                                     │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  index.html  (SPA — vanilla JS, Chart.js)            │    │
│  │                                                      │    │
│  │  • No auth libraries — session cookie is HTTP-only   │    │
│  │  • All /api/* requests sent with same-origin cookie  │    │
│  │  • Identity decoded from access token claims         │    │
│  └──────────────────────────┬───────────────────────────┘    │
│                             │ HTTP (HOST_BIND:HOST_PORT)      │
│  ┌──────────────────────────▼───────────────────────────┐    │
│  │          oauth2-proxy  (sole public entry point)      │    │
│  │                                                      │    │
│  │  • Enforces Entra ID login before serving anything   │    │
│  │  • Validates OIDC session; issues HTTP-only cookie   │    │
│  │  • Injects X-Auth-Request-Email and                  │    │
│  │    X-Auth-Request-Access-Token headers upstream      │    │
│  │  • Handles /oauth2/* routes (login, callback,        │    │
│  │    sign_out)                                         │    │
│  └──────────────────────────┬───────────────────────────┘    │
│                             │ internal Docker network         │
│  ┌──────────────────────────▼───────────────────────────┐    │
│  │               Nginx  (nginx container)                │    │
│  │                                                      │    │
│  │  • Serves index.html and static assets               │    │
│  │  • Serves /config.js (generated at container start)  │    │
│  │  • Strips client-supplied identity headers           │    │
│  │  • Forwards oauth2-proxy identity headers to /api/*  │    │
│  │  • No host port exposed — internal only              │    │
│  └──────────────────────────┬───────────────────────────┘    │
│                             │ internal Docker network         │
│  ┌──────────────────────────▼───────────────────────────┐    │
│  │        Node.js / Express  (api container)             │    │
│  │                                                      │    │
│  │  • Reads identity from X-Auth-Request-* headers      │    │
│  │  • Decodes (does not verify) access token for OID    │    │
│  │    and display name — signature already verified     │    │
│  │    by oauth2-proxy                                   │    │
│  │  • RBAC: admin / user roles + domain assignments     │    │
│  │  • GET/PUT /api/assessment (per-user, scoped)        │    │
│  │  • GET /api/me                                       │    │
│  │  • Admin endpoints: users, roles, assignments,       │    │
│  │    merged assessment view, snapshots                 │    │
│  └──────────────────────────┬───────────────────────────┘    │
│                             │                                 │
│  ┌──────────────────────────▼───────────────────────────┐    │
│  │            SQLite  (named Docker volume)              │    │
│  │  tables: assessments, users, assignments, snapshots  │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
                             │
             ┌───────────────▼───────────────┐
             │      Microsoft Entra ID        │
             │  (OIDC token issuance only;    │
             │   signature verification done  │
             │   inside oauth2-proxy)         │
             └───────────────────────────────┘
```

### File structure

```
AESCSFv2/
├── index.html              Single-page application (HTML + CSS + JS)
├── config.js               Local dev config; overwritten at container start
│                           by nginx/entrypoint.sh
├── docker-compose.yml      On-prem stack: oauth2-proxy + nginx + api
├── .env.example            Configuration reference (copy to .env)
│
├── nginx/
│   ├── Dockerfile          nginx:alpine image
│   ├── nginx.conf          Identity-header stripping, SPA routing, /api proxy
│   └── entrypoint.sh       Generates /config.js from env vars at startup
│
└── server/
    ├── server.js           Express API — auth, RBAC, assessment CRUD, snapshots
    ├── package.json        Dependencies: express, better-sqlite3, helmet, cors
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

Browse to `http://192.168.1.10` — oauth2-proxy will immediately redirect to the Microsoft sign-in page. After successful authentication you are returned to the app.

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

1. Every user who passes the oauth2-proxy login is automatically registered in the database.
2. The **first** user to sign in is made Admin (or you can pin admins via `AESCSF_ADMIN_OIDS`).
3. The Admin opens the **Admin** tab and assigns domains to each user — e.g. the network team gets `ARCHITECTURE` and `ACCESS`, the risk team gets `RISK` and `THREAT`.
4. Users log in and see only their assigned domains in the Assessment and Dashboard views. The domain filter dropdown is also restricted to their scope.
5. Users fill in evidence, status, owners, and remediation notes for their practices.
6. The Admin can click **Load Merged View** to overlay a consolidated assessment that combines all users' contributions, merged by domain ownership.

### Admin panel

The **Admin** tab provides:

- **User cards** — name, email, role badge, role toggle (promote/demote), domain assignment checkboxes
- **Save assignments** — updates the user's domain scope immediately
- **Load Merged View** — loads a read-only combined assessment from all users across all assigned domains; a banner indicates merged mode with a **Restore my view** button

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
| `GET` | `/api/admin/assessment/merged` | Admin | Merged assessment from all users by domain ownership |
| `GET` | `/api/snapshots` | User | List the current user's saved snapshots |
| `POST` | `/api/snapshots` | User | Save a named snapshot of the current assessment |
| `GET` | `/api/snapshots/:id` | User | Load full data for a specific snapshot |
| `DELETE` | `/api/snapshots/:id` | User | Delete a snapshot (own snapshots only) |

---

## Security Implementation

### Network layer

- **Docker port binding** — the host port is bound to `HOST_BIND` (your internal NIC IP), not `0.0.0.0`. The application socket is never opened on internet-facing interfaces.
- **oauth2-proxy as sole entry point** — Nginx and the API container have no host ports exposed. All traffic enters through oauth2-proxy only.
- **CORS** — `ALLOWED_ORIGIN` must be explicitly set; there is no wildcard `*` default in production.

### Authentication

- **oauth2-proxy** (`quay.io/oauth2-proxy/oauth2-proxy:v7.6.0`) sits in front of Nginx and acts as the infrastructure-level authentication gate. No HTML, JavaScript, or API response is served to unauthenticated clients — the OIDC handshake is completed entirely server-side before any application content is returned.
- The session is maintained via an **HTTP-only, SameSite=Lax** cookie (`_aescsf_session`). The cookie is inaccessible to browser JavaScript and is forwarded automatically on same-origin requests.
- After authentication, oauth2-proxy injects `X-Auth-Request-Email` and `X-Auth-Request-Access-Token` headers into requests forwarded to Nginx and the API.
- Nginx **strips any client-supplied** `X-Auth-Request-*` headers before forwarding to the API, then re-injects the proxy-validated values. This prevents identity spoofing even on the internal Docker network.
- The API decodes (but does not re-verify) the access token payload to extract the Entra ID Object ID (`oid`) and display name. The token signature was already validated by oauth2-proxy; re-verifying would require the API to hold tenant JWKS credentials, adding unnecessary complexity.
- No auth libraries (MSAL.js, jsonwebtoken, jwks-rsa) are present in the browser or API code.

### Sign-out

Clicking **Sign out** in the application navigates to `/oauth2/sign_out`, which clears the oauth2-proxy session cookie and redirects to the Entra ID logout endpoint.

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
- `express.json` body size is capped at `4 MB`.
- SQLite WAL mode and foreign-key constraints are enabled.
- All SQL interactions use prepared statements — no string interpolation.
- The API container is not exposed on the host network; it is only reachable through Nginx on the internal Docker network.

### Runtime configuration

- No secrets are baked into container images. `AESCSF_CLIENT_SECRET` and `OAUTH2_PROXY_COOKIE_SECRET` live only in the `.env` file and are injected at runtime via Docker Compose environment variables.
- Nginx generates `/config.js` from environment variables at container start via `nginx/entrypoint.sh`. The file contains only non-sensitive runtime settings (storage mode, API path).

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
