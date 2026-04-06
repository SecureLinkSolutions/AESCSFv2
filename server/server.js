"use strict";

/**
 * AESCSF v2 Evidence Tracker — on-prem API server
 *
 * Authentication: validates EntraID RS256 JWT Bearer tokens.
 * RBAC:
 *   admin — "assessment master"; can see/edit all domains, manage users,
 *           view the merged assessment across all contributors.
 *   user  — can only view and edit their assigned domains.
 *
 * Routes:
 *   GET  /api/health                        liveness probe (no auth)
 *   GET  /api/me                            current user profile + role + domains
 *   GET  /api/assessment                    load own assessment
 *   PUT  /api/assessment                    save own assessment (users: restricted to assigned domains)
 *   GET  /api/admin/users                   list all registered users  [admin]
 *   PUT  /api/admin/users/:oid/role         set a user's role          [admin]
 *   PUT  /api/admin/users/:oid/assignments  set a user's domain list   [admin]
 *   GET  /api/admin/assessment/merged       merged view from all users [admin]
 *
 * Environment variables:
 *   ENTRA_TENANT_ID    Azure AD tenant GUID
 *   ENTRA_CLIENT_ID    App registration client/application GUID
 *   AESCSF_ADMIN_OIDS  Comma-separated EntraID OIDs that are always admins
 *                      (optional — if empty the first registered user becomes admin)
 *   PORT               Listening port (default: 3000)
 *   DATA_DIR           SQLite database directory (default: /data)
 *   ALLOWED_ORIGIN     CORS allowed origin
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
const TENANT_ID   = process.env.ENTRA_TENANT_ID  || "";
const CLIENT_ID   = process.env.ENTRA_CLIENT_ID  || "";
const PORT        = parseInt(process.env.PORT     || "3000", 10);
const DATA_DIR    = process.env.DATA_DIR          || "/data";
const ADMIN_OIDS  = (process.env.AESCSF_ADMIN_OIDS || "")
                      .split(",").map(s => s.trim()).filter(Boolean);

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
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS assessments (
    user_oid    TEXT    NOT NULL,
    tenant_id   TEXT    NOT NULL DEFAULT '',
    username    TEXT    NOT NULL DEFAULT '',
    data        TEXT    NOT NULL,
    updated_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (user_oid, tenant_id)
  );

  CREATE TABLE IF NOT EXISTS users (
    oid          TEXT    PRIMARY KEY,
    tenant_id    TEXT    NOT NULL DEFAULT '',
    username     TEXT    NOT NULL DEFAULT '',
    display_name TEXT    NOT NULL DEFAULT '',
    role         TEXT    NOT NULL DEFAULT 'user'
                         CHECK(role IN ('admin','user')),
    created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    last_seen    INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS assignments (
    user_oid    TEXT    NOT NULL REFERENCES users(oid) ON DELETE CASCADE,
    domain      TEXT    NOT NULL,
    assigned_by TEXT    NOT NULL DEFAULT '',
    assigned_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (user_oid, domain)
  );
`);

/* ── Prepared statements ─────────────────────────────────────────────────── */
const stmtGetAssessment = db.prepare(
  "SELECT data FROM assessments WHERE user_oid = ? AND tenant_id = ?"
);
const stmtUpsertAssessment = db.prepare(`
  INSERT INTO assessments (user_oid, tenant_id, username, data, updated_at)
  VALUES (?, ?, ?, ?, unixepoch())
  ON CONFLICT(user_oid, tenant_id) DO UPDATE SET
    username   = excluded.username,
    data       = excluded.data,
    updated_at = excluded.updated_at
`);

const stmtGetUser = db.prepare("SELECT * FROM users WHERE oid = ?");
const stmtUpsertUser = db.prepare(`
  INSERT INTO users (oid, tenant_id, username, display_name, role, last_seen)
  VALUES (?, ?, ?, ?, ?, unixepoch())
  ON CONFLICT(oid) DO UPDATE SET
    username     = excluded.username,
    display_name = excluded.display_name,
    last_seen    = excluded.last_seen
`);
const stmtSetRole = db.prepare(
  "UPDATE users SET role = ? WHERE oid = ?"
);
const stmtCountAdmins = db.prepare(
  "SELECT COUNT(*) AS n FROM users WHERE role = 'admin'"
);
const stmtGetAllUsers = db.prepare(
  "SELECT oid, username, display_name, role, created_at, last_seen FROM users ORDER BY display_name"
);
const stmtGetAssignments = db.prepare(
  "SELECT domain FROM assignments WHERE user_oid = ? ORDER BY domain"
);
const stmtGetAllAssignments = db.prepare(
  "SELECT user_oid, domain FROM assignments ORDER BY user_oid, domain"
);
const stmtDeleteAssignments = db.prepare(
  "DELETE FROM assignments WHERE user_oid = ?"
);
const stmtInsertAssignment = db.prepare(
  "INSERT OR REPLACE INTO assignments (user_oid, domain, assigned_by, assigned_at) VALUES (?, ?, ?, unixepoch())"
);
const stmtGetAllAssessments = db.prepare(
  "SELECT a.user_oid, a.data FROM assessments a JOIN users u ON a.user_oid = u.oid AND a.tenant_id = u.tenant_id"
);

/* ── JWKS client ─────────────────────────────────────────────────────────── */
const jwks = SSO_ENABLED
  ? jwksClient({
      jwksUri: `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`,
      cache: true, rateLimit: true, cacheMaxEntries: 10, cacheMaxAge: 3600000
    })
  : null;

function getSigningKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

/* ── Middleware: authenticate ────────────────────────────────────────────── */
function requireAuth(req, res, next) {
  if (!SSO_ENABLED) {
    req.user = { oid: "anonymous", tenant: "", username: "anonymous", display_name: "Anonymous" };
    return next();
  }
  const authHeader = req.headers["authorization"] || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Bearer token" });
  }
  jwt.verify(
    authHeader.slice(7),
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
        oid:          decoded.oid      || decoded.sub,
        tenant:       decoded.tid      || TENANT_ID,
        username:     decoded.preferred_username || decoded.upn || decoded.email || decoded.oid,
        display_name: decoded.name     || decoded.preferred_username || decoded.oid
      };
      next();
    }
  );
}

/* ── Middleware: auto-register user + determine role ─────────────────────── */
function autoRegister(req, res, next) {
  const { oid, tenant, username, display_name } = req.user;

  /* Determine the role to assign */
  let role = "user";

  /* Hard-coded admins from env */
  if (ADMIN_OIDS.includes(oid)) {
    role = "admin";
  } else {
    const existing = stmtGetUser.get(oid);
    if (existing) {
      role = existing.role; /* keep existing role */
    } else {
      /* First user ever → bootstrap as admin */
      const adminCount = stmtCountAdmins.get().n;
      if (adminCount === 0) role = "admin";
    }
  }

  stmtUpsertUser.run(oid, tenant, username, display_name, role);

  /* If this user is in ADMIN_OIDS but their DB record isn't admin yet, fix it */
  if (ADMIN_OIDS.includes(oid)) {
    stmtSetRole.run("admin", oid);
    role = "admin";
  }

  req.dbUser = stmtGetUser.get(oid);
  next();
}

/* ── Middleware: require admin role ──────────────────────────────────────── */
function requireAdmin(req, res, next) {
  if (!req.dbUser || req.dbUser.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function getUserAssignments(oid) {
  return stmtGetAssignments.all(oid).map(r => r.domain);
}

/**
 * Merge all users' assessment data based on their domain assignments.
 * For each domain, find the user(s) assigned to it and combine their practices.
 * If multiple users are assigned the same domain, the most-complete entry wins.
 */
function buildMergedAssessment() {
  /* Build domain → [oids] map */
  const allAssignments = stmtGetAllAssignments.all();
  const domainOwners = {};
  for (const { user_oid, domain } of allAssignments) {
    if (!domainOwners[domain]) domainOwners[domain] = [];
    domainOwners[domain].push(user_oid);
  }

  /* Load all assessments */
  const allRows = stmtGetAllAssessments.all();
  const assessmentsByOid = {};
  for (const row of allRows) {
    try { assessmentsByOid[row.user_oid] = JSON.parse(row.data); } catch { /* skip */ }
  }

  /* Build merged assessments object */
  const merged = {};
  for (const [domain, ownerOids] of Object.entries(domainOwners)) {
    for (const ownerOid of ownerOids) {
      const ownerData = assessmentsByOid[ownerOid]?.assessments || {};
      for (const [practiceId, assessment] of Object.entries(ownerData)) {
        /* Only include practices that belong to this domain */
        if (!practiceId.startsWith(domain + "-") && !practiceId.startsWith(domain.replace("-", "") + "-")) {
          /* Try prefix match: ACCESS-1a starts with "ACCESS" */
          if (!practiceId.toUpperCase().startsWith(domain.split("-")[0])) continue;
        }
        /* Prefer the most-complete entry */
        const existing = merged[practiceId];
        const newScore = scoreAssessment(assessment);
        const oldScore = existing ? scoreAssessment(existing) : -1;
        if (newScore > oldScore) merged[practiceId] = assessment;
      }
    }
  }

  return { assessments: merged, _mergedView: true };
}

function scoreAssessment(a) {
  if (!a) return -1;
  let s = 0;
  if (a.status && a.status !== "Not Assessed") s += 2;
  if (a.evidence && a.evidence.trim()) s += 1;
  if (a.owner && a.owner.trim()) s += 1;
  return s;
}

/* ── Express app ─────────────────────────────────────────────────────────── */
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || false,
  methods: ["GET", "PUT", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "4mb" }));

/* ── Routes ─────────────────────────────────────────────────────────────── */

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", sso: SSO_ENABLED, ts: Date.now() });
});

/* Current user profile — also auto-registers the user on first call */
app.get("/api/me", requireAuth, autoRegister, (req, res) => {
  const domains = getUserAssignments(req.user.oid);
  res.json({
    oid:         req.dbUser.oid,
    username:    req.dbUser.username,
    displayName: req.dbUser.display_name,
    role:        req.dbUser.role,
    domains
  });
});

/* Load this user's assessment */
app.get("/api/assessment", requireAuth, autoRegister, (req, res) => {
  const row = stmtGetAssessment.get(req.user.oid, req.user.tenant);
  if (!row) return res.status(404).json({ error: "No assessment found" });
  try {
    res.json(JSON.parse(row.data));
  } catch {
    res.status(500).json({ error: "Corrupt assessment data" });
  }
});

/* Save this user's assessment */
app.put("/api/assessment", requireAuth, autoRegister, (req, res) => {
  if (!req.body || typeof req.body !== "object") {
    return res.status(400).json({ error: "Body must be a JSON object" });
  }

  const isAdmin = req.dbUser.role === "admin";
  let payload   = req.body;

  /* Non-admins: strip any practices outside their assigned domains */
  if (!isAdmin) {
    const allowedDomains = new Set(getUserAssignments(req.user.oid));
    if (allowedDomains.size > 0 && payload.assessments) {
      const filtered = {};
      for (const [practiceId, data] of Object.entries(payload.assessments)) {
        const domain = practiceId.split("-")[0];
        if (allowedDomains.has(domain)) filtered[practiceId] = data;
      }
      payload = { ...payload, assessments: filtered };
    }
  }

  try {
    stmtUpsertAssessment.run(
      req.user.oid, req.user.tenant, req.user.username,
      JSON.stringify(payload)
    );
    res.json({ saved: true });
  } catch (err) {
    console.error("[AESCSF API] DB write error:", err);
    res.status(500).json({ error: "Failed to save assessment" });
  }
});

/* ── Admin routes ────────────────────────────────────────────────────────── */

/* List all registered users with their roles and domain assignments */
app.get("/api/admin/users", requireAuth, autoRegister, requireAdmin, (_req, res) => {
  const users = stmtGetAllUsers.all();
  const allAssignments = stmtGetAllAssignments.all();

  const assignmentsByOid = {};
  for (const { user_oid, domain } of allAssignments) {
    if (!assignmentsByOid[user_oid]) assignmentsByOid[user_oid] = [];
    assignmentsByOid[user_oid].push(domain);
  }

  res.json(users.map(u => ({
    ...u,
    domains: assignmentsByOid[u.oid] || []
  })));
});

/* Set a user's role */
app.put("/api/admin/users/:oid/role", requireAuth, autoRegister, requireAdmin, (req, res) => {
  const { role } = req.body || {};
  if (!["admin", "user"].includes(role)) {
    return res.status(400).json({ error: "role must be 'admin' or 'user'" });
  }
  const target = stmtGetUser.get(req.params.oid);
  if (!target) return res.status(404).json({ error: "User not found" });

  stmtSetRole.run(role, req.params.oid);
  res.json({ updated: true, oid: req.params.oid, role });
});

/* Set a user's domain assignments (replaces existing) */
app.put("/api/admin/users/:oid/assignments", requireAuth, autoRegister, requireAdmin, (req, res) => {
  const { domains } = req.body || {};
  if (!Array.isArray(domains)) {
    return res.status(400).json({ error: "domains must be an array of strings" });
  }
  const target = stmtGetUser.get(req.params.oid);
  if (!target) return res.status(404).json({ error: "User not found" });

  const setAssignments = db.transaction((oid, domainList, byOid) => {
    stmtDeleteAssignments.run(oid);
    for (const domain of domainList) {
      stmtInsertAssignment.run(oid, domain.toUpperCase(), byOid);
    }
  });

  try {
    setAssignments(req.params.oid, domains, req.user.oid);
    res.json({ updated: true, oid: req.params.oid, domains });
  } catch (err) {
    console.error("[AESCSF API] Assignment update error:", err);
    res.status(500).json({ error: "Failed to update assignments" });
  }
});

/* Merged assessment — combines all users' data based on their domain assignments */
app.get("/api/admin/assessment/merged", requireAuth, autoRegister, requireAdmin, (_req, res) => {
  try {
    res.json(buildMergedAssessment());
  } catch (err) {
    console.error("[AESCSF API] Merge error:", err);
    res.status(500).json({ error: "Failed to build merged assessment" });
  }
});

/* ── Start ───────────────────────────────────────────────────────────────── */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[AESCSF API] Listening on port ${PORT}`);
  console.log(`[AESCSF API] SSO: ${SSO_ENABLED ? `EntraID tenant ${TENANT_ID}` : "DISABLED"}`);
  console.log(`[AESCSF API] Admin OIDs: ${ADMIN_OIDS.length ? ADMIN_OIDS.join(", ") : "(first user will become admin)"}`);
  console.log(`[AESCSF API] DB:  ${path.join(DATA_DIR, "aescsf.db")}`);
});
