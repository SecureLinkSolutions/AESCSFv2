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
| Year-on-year comparison | Load a previous assessment and compare domain scores side-by-side |
| PDF report | Full assessment report with radar charts, domain summary, and gap register |
| AEMO CSV export | Practice status in the AEMO-required CSV template format |
| Gap register export | Filtered CSV of open gaps and remediation actions |
| JSON backup / restore | Full assessment import and export for backup or transfer |
| EntraID SSO | Microsoft Entra ID (Azure AD) authentication via MSAL.js |
| RBAC | Admin (assessment master) and User (assigned domains only) roles |
| On-prem deployment | Docker Compose stack — Nginx + Node.js API + SQLite |

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     Internal Network                      │
│                                                          │
│  Browser                                                 │
│  ┌────────────────────────────────────────────────────┐  │
│  │  index.html  (SPA — vanilla JS, Chart.js, MSAL.js) │  │
│  │                                                    │  │
│  │  • MSAL.js authenticates against Entra ID (cloud) │  │
│  │  • Bearer token attached to all /api/* requests   │  │
│  └───────────────────────┬────────────────────────────┘  │
│                          │ HTTP (port 80)                 │
│  ┌───────────────────────▼────────────────────────────┐  │
│  │            Nginx (frontend container)              │  │
│  │                                                    │  │
│  │  • Serves index.html and static assets            │  │
│  │  • Serves /config.js (runtime EntraID config)     │  │
│  │  • RFC 1918 IP allowlist — denies all external IPs│  │
│  │  • Proxies /api/* → backend container             │  │
│  └───────────────────────┬────────────────────────────┘  │
│                          │ internal Docker network        │
│  ┌───────────────────────▼────────────────────────────┐  │
│  │          Node.js / Express (api container)         │  │
│  │                                                    │  │
│  │  • Validates RS256 JWT (Entra ID JWKS endpoint)   │  │
│  │  • RBAC: admin / user roles + domain assignments  │  │
│  │  • GET/PUT /api/assessment (per-user, scoped)     │  │
│  │  • GET /api/me                                    │  │
│  │  • Admin endpoints: users, roles, assignments,    │  │
│  │    merged assessment view                         │  │
│  └───────────────────────┬────────────────────────────┘  │
│                          │                               │
│  ┌───────────────────────▼────────────────────────────┐  │
│  │            SQLite (named Docker volume)            │  │
│  │  tables: assessments, users, assignments           │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
                          │
              ┌───────────▼───────────┐
              │  Microsoft Entra ID   │
              │  (token issuance +    │
              │   JWKS verification)  │
              └───────────────────────┘
```

### File structure

```
AESCSFv2/
├── index.html              Single-page application (HTML + CSS + JS)
├── config.js               Local dev config (clientId/tenantId); overwritten
│                           at container start by nginx/entrypoint.sh
├── docker-compose.yml      On-prem stack definition
├── .env.example            Configuration reference (copy to .env)
│
├── nginx/
│   ├── Dockerfile          nginx:alpine image
│   ├── nginx.conf          RFC 1918 allowlist, SPA routing, /api proxy
│   └── entrypoint.sh       Generates /config.js from env vars at startup
│
└── server/
    ├── server.js           Express API — auth, RBAC, assessment CRUD
    ├── package.json        Dependencies: express, jsonwebtoken, jwks-rsa,
    │                       better-sqlite3, helmet, cors
    └── Dockerfile          node:20-alpine image
```

---

## Deployment

### Prerequisites

- Docker and Docker Compose installed on the host machine
- The host must be reachable only from your internal network (see [Security](#security-implementation))
- A Microsoft Entra ID (Azure AD) app registration (see [EntraID SSO Registration](#entraid-sso-registration))

### Steps

**1. Clone and configure**

```bash
git clone https://github.com/SecureLinkSolutions/AESCSFv2.git
cd AESCSFv2
cp .env.example .env
```

Edit `.env` and fill in your values:

```env
AESCSF_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx   # App registration client ID
AESCSF_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx   # Azure AD tenant ID

# Optional: pin admins by their Entra ID Object ID (comma-separated)
# If blank, the first user to sign in becomes admin automatically.
# AESCSF_ADMIN_OIDS=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

AESCSF_STORAGE_MODE=api        # "api" = SQLite backend (recommended)
HOST_BIND=192.168.1.10         # Your server's internal NIC IP
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

Browse to `http://192.168.1.10` — the Microsoft sign-in screen will appear.

**4. First sign-in = first admin**

The first user to sign in is automatically assigned the **Admin** role. They can then assign roles and domains to subsequent users via the **Admin** tab.

---

## EntraID SSO Registration

1. Sign in to [portal.azure.com](https://portal.azure.com)
2. Go to **Microsoft Entra ID → App registrations → + New registration**
   - Name: `AESCSF v2 Evidence Tracker`
   - Supported account types: **Accounts in this organizational directory only**
   - Redirect URI: **Web** → `http://<YOUR-SERVER-IP>/` (e.g. `http://192.168.1.10/`)
3. Note the **Application (client) ID** → `AESCSF_CLIENT_ID`
4. Note the **Directory (tenant) ID** → `AESCSF_TENANT_ID`
5. Go to **Expose an API → + Add a scope**
   - Application ID URI: accept the default (`api://<client-id>`)
   - Scope name: `Assessment.ReadWrite`
   - Who can consent: `Admins and users`
   - Display name / Description: `Read and write AESCSF assessment data`
6. Go to **API permissions → + Add a permission → My APIs → your app**
   - Tick `Assessment.ReadWrite` → **Add permissions**
   - Click **Grant admin consent for \<your tenant\>**

---

## RBAC — Roles and Access Control

### Roles

| Role | Assessment view | Can edit | Admin tab |
|---|---|---|---|
| **Admin** (Assessment Master) | All 11 domains | All domains | Yes |
| **User** | Assigned domains only | Assigned domains only | No |

### How it works

1. Every user who signs in is automatically registered in the database.
2. The **first** user to sign in is made Admin (or you can pin admins via `AESCSF_ADMIN_OIDS`).
3. The Admin opens the **Admin** tab and assigns domains to each user — e.g. the network team gets `ARCHITECTURE` and `ACCESS`, the risk team gets `RISK` and `THREAT`.
4. Users log in and see only their assigned domains in the Assessment and Dashboard views. The domain filter dropdown is also restricted to their scope.
5. Users fill in evidence, status, owners, and remediation notes for their practices.
6. The Admin can click **Load Merged View** in the Admin tab to overlay a consolidated assessment that combines all users' contributions, merged by domain ownership.

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

---

## Security Implementation

### Network layer

- **Docker port binding** — the host port is bound to `HOST_BIND` (your internal NIC IP), not `0.0.0.0`. The application socket is never opened on internet-facing interfaces.
- **Nginx IP allowlist** — all requests from outside RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and localhost receive a `403` before any application logic is reached.
- **CORS** — `ALLOWED_ORIGIN` must be explicitly set; there is no wildcard `*` default in production.

### Authentication

- **MSAL.js 2.x** (Microsoft Authentication Library) runs in the browser and handles the OAuth 2.0 authorisation code flow with PKCE against Microsoft Entra ID.
- Tokens are stored in `sessionStorage` (cleared on browser close).
- Every API request includes an `Authorization: Bearer <token>` header.
- The backend verifies RS256 JWT signatures using the **JWKS endpoint** of your Entra ID tenant (`https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys`). Tokens are validated for correct `audience` (your client ID) and `issuer`.
- Token refresh is handled silently by MSAL; if interaction is required the user is redirected to the Entra ID login page.

### Authorisation (RBAC)

- Role (`admin` / `user`) is stored server-side in SQLite and checked on every request — it cannot be elevated by the client.
- Non-admin users who attempt to save practices outside their assigned domains have those entries **silently stripped** by the backend before persistence.
- Admin-only endpoints (`/api/admin/*`) return `403` for any non-admin token regardless of what the client sends.

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
- The API container is not exposed on the host network; it is only reachable through the Nginx reverse proxy on the internal Docker network.

### Runtime configuration

- `clientId` and `tenantId` are **never baked into the container image**. Nginx generates `/config.js` from environment variables at container start via `nginx/entrypoint.sh`.
- Secrets live only in the `.env` file on the host and are injected via Docker Compose environment variables.

---

## Local Development (no Docker)

For local testing without Docker, open `index.html` directly in a browser. Edit `config.js` to add your `clientId` and `tenantId` (or leave them blank to skip authentication). Data will be stored in browser `localStorage`.

To run the API locally:

```bash
cd server
npm install
ENTRA_TENANT_ID=... ENTRA_CLIENT_ID=... DATA_DIR=./data node server.js
```

The frontend will need `storageMode: "api"` set in `config.js` and the API running on port 3000.

---

## Disclaimer

This tool is provided for assessment and evidence tracking purposes only and does not guarantee compliance with AESCSF or any regulatory requirement. Users are responsible for validating assessments, evidence, and compliance outcomes.

AI was used in creating this tool.
