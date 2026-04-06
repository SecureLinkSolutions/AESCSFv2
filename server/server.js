"use strict";

/**
 * AESCSF v2 Evidence Tracker — on-prem API server
 *
 * Validates EntraID JWT Bearer tokens issued by your tenant, then exposes:
 *   GET  /api/assessment   → load this user's assessment from SQLite
 *   PUT  /api/assessment   → save this user's assessment to SQLite
 *   GET  /api/health       → liveness probe (no auth required)
 *
 * Data is stored per-user (keyed by the token's `oid` claim — the
 * EntraID Object ID — so every authenticated user has their own assessment).
 *
 * Environment variables (all required when SSO is enabled):
 *   ENTRA_TENANT_ID   — Azure AD tenant GUID
 *   ENTRA_CLIENT_ID   — App registration client/application GUID
 *   PORT              — Listening port (default: 3000)
 *   DATA_DIR          — Directory for the SQLite database (default: /data)
 */

const express    = require("express");
const helmet     = require("helmet");
const cors       = require("cors");
const jwt        = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const Database   = require("better-sqlite3");
const path       = require("path");
const fs         = require("fs");

/* ── Config ─────────────────────────────────────────────────────────────── */
const TENANT_ID = process.env.ENTRA_TENANT_ID  || "";
const CLIENT_ID = process.env.ENTRA_CLIENT_ID  || "";
const PORT      = parseInt(process.env.PORT     || "3000", 10);
const DATA_DIR  = process.env.DATA_DIR          || "/data";

const SSO_ENABLED = !!(TENANT_ID && CLIENT_ID);

if (!SSO_ENABLED) {
  console.warn(
    "[AESCSF API] ENTRA_TENANT_ID / ENTRA_CLIENT_ID not set — " +
    "running WITHOUT authentication. Do not expose this to untrusted networks!"
  );
}

/* ── Database ────────────────────────────────────────────────────────────── */
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, "aescsf.db"));

db.exec(`
  CREATE TABLE IF NOT EXISTS assessments (
    user_oid    TEXT    NOT NULL,
    tenant_id   TEXT    NOT NULL DEFAULT '',
    username    TEXT    NOT NULL DEFAULT '',
    data        TEXT    NOT NULL,
    updated_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (user_oid, tenant_id)
  );
`);

const stmtGet = db.prepare(
  "SELECT data FROM assessments WHERE user_oid = ? AND tenant_id = ?"
);
const stmtUpsert = db.prepare(`
  INSERT INTO assessments (user_oid, tenant_id, username, data, updated_at)
  VALUES (?, ?, ?, ?, unixepoch())
  ON CONFLICT(user_oid, tenant_id) DO UPDATE SET
    username   = excluded.username,
    data       = excluded.data,
    updated_at = excluded.updated_at
`);

/* ── JWKS client for EntraID token verification ─────────────────────────── */
const jwks = SSO_ENABLED
  ? jwksClient({
      jwksUri: `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`,
      cache: true,
      rateLimit: true,
      cacheMaxEntries: 10,
      cacheMaxAge: 3600000
    })
  : null;

function getSigningKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

/* ── JWT middleware ──────────────────────────────────────────────────────── */
function requireAuth(req, res, next) {
  if (!SSO_ENABLED) {
    /* No SSO config — allow all requests with a synthetic anon identity */
    req.user = { oid: "anonymous", tenant: "", username: "anonymous" };
    return next();
  }

  const authHeader = req.headers["authorization"] || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Bearer token" });
  }

  const token = authHeader.slice(7);

  jwt.verify(
    token,
    getSigningKey,
    {
      algorithms: ["RS256"],
      audience:   CLIENT_ID,
      issuer: [
        `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
        `https://sts.windows.net/${TENANT_ID}/`
      ]
    },
    (err, decoded) => {
      if (err) {
        console.error("[AESCSF API] Token verification failed:", err.message);
        return res.status(401).json({ error: "Invalid or expired token" });
      }
      req.user = {
        oid:      decoded.oid      || decoded.sub,
        tenant:   decoded.tid      || TENANT_ID,
        username: decoded.preferred_username || decoded.upn || decoded.email || decoded.oid
      };
      next();
    }
  );
}

/* ── Express app ─────────────────────────────────────────────────────────── */
const app = express();

app.use(helmet({
  /* The frontend is served by Nginx, not this server */
  contentSecurityPolicy: false
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || "*",
  methods: ["GET", "PUT", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "4mb" }));

/* ── Routes ─────────────────────────────────────────────────────────────── */
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", sso: SSO_ENABLED, ts: Date.now() });
});

app.get("/api/assessment", requireAuth, (req, res) => {
  const row = stmtGet.get(req.user.oid, req.user.tenant);
  if (!row) return res.status(404).json({ error: "No assessment found" });
  try {
    res.json(JSON.parse(row.data));
  } catch {
    res.status(500).json({ error: "Corrupt assessment data" });
  }
});

app.put("/api/assessment", requireAuth, (req, res) => {
  if (!req.body || typeof req.body !== "object") {
    return res.status(400).json({ error: "Body must be a JSON object" });
  }
  try {
    stmtUpsert.run(
      req.user.oid,
      req.user.tenant,
      req.user.username,
      JSON.stringify(req.body)
    );
    res.json({ saved: true });
  } catch (err) {
    console.error("[AESCSF API] DB write error:", err);
    res.status(500).json({ error: "Failed to save assessment" });
  }
});

/* ── Start ───────────────────────────────────────────────────────────────── */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[AESCSF API] Listening on port ${PORT}`);
  console.log(`[AESCSF API] SSO: ${SSO_ENABLED ? `EntraID tenant ${TENANT_ID}` : "DISABLED"}`);
  console.log(`[AESCSF API] DB:  ${path.join(DATA_DIR, "aescsf.db")}`);
});
