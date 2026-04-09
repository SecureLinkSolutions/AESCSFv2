"use strict";

/**
 * AESCSF v2 Evidence Tracker — on-prem API server
 *
 * Authentication: identity is established by oauth2-proxy, which validates
 * the Entra ID session before forwarding requests. The proxy injects:
 *   X-Auth-Request-Email        — user's email / UPN
 *   X-Auth-Request-Access-Token — raw JWT (already verified by the proxy)
 *
 * The API decodes (but does NOT re-verify) the access token to extract the
 * user's stable OID. This is safe because:
 *   • oauth2-proxy already verified the RS256 signature via Entra ID JWKS
 *   • The API is only reachable from oauth2-proxy via the internal Docker network
 *   • Nginx strips any X-Auth-Request-* headers from client requests before they
 *     reach the API, so only proxy-injected values are trusted
 *
 * RBAC:
 *   admin — "assessment master"; full access + user management + merged view
 *   user  — restricted to their assigned domains
 *
 * Environment variables:
 *   AESCSF_SSO_ENABLED  "true" (default) — enforce proxy-header auth
 *                       "false"           — allow anonymous (local dev only)
 *   AESCSF_ADMIN_OIDS   Comma-separated OIDs always treated as admin
 *   PORT                Listening port (default 3000)
 *   DATA_DIR            SQLite + uploads directory (default /data)
 *   ALLOWED_ORIGIN      CORS allowed origin
 */

const express  = require("express");
const helmet   = require("helmet");
const cors     = require("cors");
const Database = require("better-sqlite3");
const multer   = require("multer");
const path     = require("path");
const fs       = require("fs");
const crypto   = require("crypto");

/* ── Config ─────────────────────────────────────────────────────────────── */
const SSO_ENABLED   = process.env.AESCSF_SSO_ENABLED !== "false"; // default true
const PORT          = parseInt(process.env.PORT || "3000", 10);
const DATA_DIR      = process.env.DATA_DIR || "/data";
const UPLOAD_DIR    = path.join(DATA_DIR, "files");
const ADMIN_OIDS    = (process.env.AESCSF_ADMIN_OIDS || "")
                        .split(",").map(s => s.trim()).filter(Boolean);
const MAX_FILE_BYTES = 20 * 1024 * 1024; // 20 MB per file
const MAX_AUDIT_VALUE_LEN = 4000; // truncate long field values in audit log

/** Fields recorded in the audit log whenever an assessment is saved. */
const AUDITED_FIELDS = [
  "status", "owner", "targetDate", "lastReviewed",
  "evidence", "notes", "gap", "attachments"
];

/** MIME types accepted for evidence file uploads. */
const ALLOWED_MIME_TYPES = new Set([
  "image/jpeg", "image/png", "image/gif", "image/webp",
  "application/pdf",
  "text/plain", "text/csv",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/msword", "application/vnd.ms-excel",
]);

if (!SSO_ENABLED) {
  console.warn(
    "[AESCSF API] AESCSF_SSO_ENABLED=false — running WITHOUT authentication. " +
    "Do not expose this to untrusted networks!"
  );
}

/* ── Directories ─────────────────────────────────────────────────────────── */
fs.mkdirSync(DATA_DIR,   { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ── Database ────────────────────────────────────────────────────────────── */
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

  CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_oid    TEXT    NOT NULL,
    tenant_id   TEXT    NOT NULL DEFAULT '',
    label       TEXT    NOT NULL,
    data        TEXT    NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_snapshots_user ON snapshots(user_oid, tenant_id);

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

  CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_oid     TEXT    NOT NULL,
    username     TEXT    NOT NULL DEFAULT '',
    display_name TEXT    NOT NULL DEFAULT '',
    practice_id  TEXT    NOT NULL,
    field        TEXT    NOT NULL,
    old_value    TEXT    NOT NULL DEFAULT '',
    new_value    TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_audit_practice ON audit_log(practice_id);
  CREATE INDEX IF NOT EXISTS idx_audit_user     ON audit_log(user_oid);
  CREATE INDEX IF NOT EXISTS idx_audit_time     ON audit_log(created_at DESC);

  CREATE TABLE IF NOT EXISTS files (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_oid     TEXT    NOT NULL,
    practice_id  TEXT    NOT NULL,
    filename     TEXT    NOT NULL,
    stored_name  TEXT    NOT NULL,
    mime_type    TEXT    NOT NULL DEFAULT '',
    size_bytes   INTEGER NOT NULL DEFAULT 0,
    uploaded_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_files_practice ON files(user_oid, practice_id);
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

const stmtListSnapshots = db.prepare(
  "SELECT id, label, created_at FROM snapshots WHERE user_oid = ? AND tenant_id = ? ORDER BY created_at DESC"
);
const stmtGetSnapshot = db.prepare(
  "SELECT id, label, data, created_at FROM snapshots WHERE id = ? AND user_oid = ? AND tenant_id = ?"
);
const stmtInsertSnapshot = db.prepare(
  "INSERT INTO snapshots (user_oid, tenant_id, label, data) VALUES (?, ?, ?, ?)"
);
const stmtDeleteSnapshot = db.prepare(
  "DELETE FROM snapshots WHERE id = ? AND user_oid = ? AND tenant_id = ?"
);

/* Audit log — statements use positional params */
const stmtInsertAudit = db.prepare(`
  INSERT INTO audit_log (user_oid, username, display_name, practice_id, field, old_value, new_value)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const stmtInsertAuditBatch = db.transaction((rows) => {
  for (const r of rows) {
    stmtInsertAudit.run(r.userOid, r.username, r.displayName, r.practiceId, r.field, r.oldValue, r.newValue);
  }
});

/* Files */
const stmtInsertFile = db.prepare(`
  INSERT INTO files (user_oid, practice_id, filename, stored_name, mime_type, size_bytes)
  VALUES (?, ?, ?, ?, ?, ?)
`);
const stmtGetFileById = db.prepare(
  "SELECT id, user_oid, practice_id, filename, stored_name, mime_type, size_bytes, uploaded_at FROM files WHERE id = ?"
);
const stmtDeleteFileRecord = db.prepare("DELETE FROM files WHERE id = ?");

/* ── Multer — evidence file upload ──────────────────────────────────────── */
const multerStorage = multer.diskStorage({
  destination(_req, _file, cb) { cb(null, UPLOAD_DIR); },
  filename(_req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, "");
    cb(null, `${crypto.randomUUID()}${ext}`);
  }
});

const upload = multer({
  storage: multerStorage,
  limits: { fileSize: MAX_FILE_BYTES },
  fileFilter(_req, file, cb) {
    if (ALLOWED_MIME_TYPES.has(file.mimetype)) return cb(null, true);
    cb(Object.assign(new Error(`File type '${file.mimetype}' is not allowed`), { code: "INVALID_MIME" }));
  }
});

/* ── JWT claims decoder (no signature verification) ─────────────────────── */
function decodeJwtClaims(token) {
  try {
    return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
  } catch { return null; }
}

/* ── Middleware: authenticate via oauth2-proxy headers ──────────────────── */
function requireAuth(req, res, next) {
  if (!SSO_ENABLED) {
    req.user = { oid: "anonymous", tenant: "", username: "anonymous", display_name: "Anonymous" };
    return next();
  }

  /* X-Auth-Request-User is the most reliably populated header for the Azure
   * provider — oauth2-proxy always sets it from preferred_username/UPN.
   * X-Auth-Request-Email may be empty when the tenant's ID token lacks an
   * `email` claim (common for Entra ID work accounts). Try user first. */
  const email = (
    req.headers["x-auth-request-user"] ||
    req.headers["x-auth-request-email"] ||
    req.headers["x-auth-request-preferred-username"] || ""
  ).trim();
  if (!email) {
    console.warn("[AESCSF] requireAuth: no identity header received. " +
      "Present headers: user=%s email=%s preferred-username=%s",
      !!req.headers["x-auth-request-user"],
      !!req.headers["x-auth-request-email"],
      !!req.headers["x-auth-request-preferred-username"]);
    return res.status(401).json({ error: "Unauthenticated — no identity from proxy" });
  }

  const rawToken  = (req.headers["x-auth-request-access-token"] || "").trim();
  let oid         = email;
  let displayName = email;
  let tenant      = "";

  if (rawToken) {
    const claims = decodeJwtClaims(rawToken);
    if (claims) {
      oid         = claims.oid  || claims.sub  || email;
      displayName = claims.name || claims.preferred_username || email;
      tenant      = claims.tid  || "";
    }
  }

  req.user = { oid, tenant, username: email, display_name: displayName };
  next();
}

/* ── Middleware: auto-register user + determine role ─────────────────────── */
function autoRegister(req, res, next) {
  const { oid, tenant, username, display_name } = req.user;

  let role = "user";
  if (ADMIN_OIDS.includes(oid)) {
    role = "admin";
  } else {
    const existing = stmtGetUser.get(oid);
    if (existing) {
      role = existing.role;
    } else {
      const adminCount = stmtCountAdmins.get().n;
      if (adminCount === 0) role = "admin";
    }
  }

  stmtUpsertUser.run(oid, tenant, username, display_name, role);

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

function buildMergedAssessment() {
  const allAssignments = stmtGetAllAssignments.all();
  const domainOwners = {};
  for (const { user_oid, domain } of allAssignments) {
    if (!domainOwners[domain]) domainOwners[domain] = [];
    domainOwners[domain].push(user_oid);
  }

  const allRows = stmtGetAllAssessments.all();
  const assessmentsByOid = {};
  for (const row of allRows) {
    try { assessmentsByOid[row.user_oid] = JSON.parse(row.data); } catch { /* skip */ }
  }

  const merged = {};

  /* Pass 1 — domain-assigned users take priority for their domain's practices */
  for (const [domain, ownerOids] of Object.entries(domainOwners)) {
    for (const ownerOid of ownerOids) {
      const ownerData = assessmentsByOid[ownerOid]?.assessments || {};
      for (const [practiceId, assessment] of Object.entries(ownerData)) {
        if (!practiceId.toUpperCase().startsWith(domain.split("-")[0])) continue;
        const existing = merged[practiceId];
        const newScore = scoreAssessment(assessment);
        const oldScore = existing ? scoreAssessment(existing) : -1;
        if (newScore > oldScore) merged[practiceId] = assessment;
      }
    }
  }

  /* Pass 2 — include ALL users' data (e.g. the admin's own assessments).
   * Users without a domain assignment (including the admin if unassigned)
   * were silently excluded in pass 1.  This pass fills in any practice that
   * has a higher-scoring entry from any contributor, regardless of assignment. */
  for (const userAssessments of Object.values(assessmentsByOid)) {
    const assessments = userAssessments?.assessments || {};
    for (const [practiceId, assessment] of Object.entries(assessments)) {
      const existing = merged[practiceId];
      const newScore = scoreAssessment(assessment);
      const oldScore = existing ? scoreAssessment(existing) : -1;
      if (newScore > oldScore) merged[practiceId] = assessment;
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

/**
 * Diff old and new assessment blobs, write changed fields to audit_log.
 * Only records changes — identical fields are skipped.
 */
function diffAndLog(user, oldData, newData) {
  const oldAssessments = (oldData?.assessments) || {};
  const newAssessments = (newData?.assessments) || {};
  const allIds = new Set([...Object.keys(oldAssessments), ...Object.keys(newAssessments)]);

  const rows = [];
  for (const practiceId of allIds) {
    const oldP = oldAssessments[practiceId] || {};
    const newP = newAssessments[practiceId] || {};
    for (const field of AUDITED_FIELDS) {
      const oldVal = String(oldP[field] ?? "").trim();
      const newVal = String(newP[field] ?? "").trim();
      if (oldVal === newVal) continue;
      rows.push({
        userOid:     user.oid,
        username:    user.username,
        displayName: user.display_name,
        practiceId,
        field,
        oldValue:    oldVal.slice(0, MAX_AUDIT_VALUE_LEN),
        newValue:    newVal.slice(0, MAX_AUDIT_VALUE_LEN),
      });
    }
  }

  if (rows.length > 0) stmtInsertAuditBatch(rows);
  return rows.length;
}

/** Build an audit query dynamically based on supplied filter params. */
function queryAudit(filters) {
  const conditions = [];
  const params     = {};

  if (filters.userOid)    { conditions.push("user_oid = @userOid");       params.userOid    = filters.userOid; }
  if (filters.practiceId) { conditions.push("practice_id = @practiceId"); params.practiceId = filters.practiceId; }
  if (filters.field)      { conditions.push("field = @field");            params.field      = filters.field; }
  if (filters.from)       { conditions.push("created_at >= @from");       params.from       = filters.from; }
  if (filters.to)         { conditions.push("created_at <= @to");         params.to         = filters.to; }

  const where  = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const base   = `FROM audit_log ${where}`;

  const total  = db.prepare(`SELECT COUNT(*) AS n ${base}`).get(params).n;

  params.limit  = Math.min(Math.max(1, parseInt(filters.limit)  || 100), 500);
  params.offset = Math.max(0, parseInt(filters.offset) || 0);

  const rows = db.prepare(
    `SELECT id, user_oid, username, display_name, practice_id, field, old_value, new_value, created_at
     ${base} ORDER BY created_at DESC LIMIT @limit OFFSET @offset`
  ).all(params);

  return { total, rows, limit: params.limit, offset: params.offset };
}

/** Format audit rows as CSV. */
function auditToCsv(rows) {
  const header = ["id", "timestamp", "user_email", "user_name", "practice_id", "field", "old_value", "new_value"];
  const escape = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines  = [header.map(escape).join(",")];
  for (const r of rows) {
    const ts = new Date(r.created_at * 1000).toISOString();
    lines.push([r.id, ts, r.username, r.display_name, r.practice_id, r.field, r.old_value, r.new_value].map(escape).join(","));
  }
  return lines.join("\r\n");
}

/** List files for a practice. Admins see all users' files; users see only their own. */
function listFilesForPractice(practiceId, userOid, isAdmin) {
  const sql = isAdmin
    ? "SELECT id, user_oid, practice_id, filename, mime_type, size_bytes, uploaded_at FROM files WHERE practice_id = ? ORDER BY uploaded_at DESC"
    : "SELECT id, user_oid, practice_id, filename, mime_type, size_bytes, uploaded_at FROM files WHERE practice_id = ? AND user_oid = ? ORDER BY uploaded_at DESC";
  return isAdmin
    ? db.prepare(sql).all(practiceId)
    : db.prepare(sql).all(practiceId, userOid);
}

/* ── Express app ─────────────────────────────────────────────────────────── */
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin:  process.env.ALLOWED_ORIGIN || false,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "4mb" }));

/* ── Routes ─────────────────────────────────────────────────────────────── */

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", sso: SSO_ENABLED, ts: Date.now() });
});

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

app.get("/api/assessment", requireAuth, autoRegister, (req, res) => {
  const row = stmtGetAssessment.get(req.user.oid, req.user.tenant);
  if (!row) return res.status(404).json({ error: "No assessment found" });
  try {
    res.json(JSON.parse(row.data));
  } catch {
    res.status(500).json({ error: "Corrupt assessment data" });
  }
});

app.put("/api/assessment", requireAuth, autoRegister, (req, res) => {
  if (!req.body || typeof req.body !== "object") {
    return res.status(400).json({ error: "Body must be a JSON object" });
  }

  const isAdmin = req.dbUser.role === "admin";
  let payload   = req.body;

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

  /* Load the existing data so we can diff before overwriting */
  let oldData = null;
  try {
    const existing = stmtGetAssessment.get(req.user.oid, req.user.tenant);
    if (existing) oldData = JSON.parse(existing.data);
  } catch { /* no existing data — first save */ }

  try {
    stmtUpsertAssessment.run(
      req.user.oid, req.user.tenant, req.user.username,
      JSON.stringify(payload)
    );
  } catch (err) {
    console.error("[AESCSF API] DB write error:", err);
    return res.status(500).json({ error: "Failed to save assessment" });
  }

  /* Write audit log entries for any changed fields (best-effort) */
  try {
    const changes = diffAndLog(req.user, oldData, payload);
    res.json({ saved: true, changes });
  } catch (auditErr) {
    console.error("[AESCSF API] Audit log error (non-fatal):", auditErr);
    res.json({ saved: true, changes: 0 });
  }
});

/* ── Admin routes ────────────────────────────────────────────────────────── */

app.get("/api/admin/users", requireAuth, autoRegister, requireAdmin, (_req, res) => {
  const users = stmtGetAllUsers.all();
  const allAssignments = stmtGetAllAssignments.all();

  const assignmentsByOid = {};
  for (const { user_oid, domain } of allAssignments) {
    if (!assignmentsByOid[user_oid]) assignmentsByOid[user_oid] = [];
    assignmentsByOid[user_oid].push(domain);
  }

  res.json(users.map(u => ({ ...u, domains: assignmentsByOid[u.oid] || [] })));
});

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

app.get("/api/admin/assessment/merged", requireAuth, autoRegister, requireAdmin, (_req, res) => {
  try {
    res.json(buildMergedAssessment());
  } catch (err) {
    console.error("[AESCSF API] Merge error:", err);
    res.status(500).json({ error: "Failed to build merged assessment" });
  }
});

/* ── Snapshot routes ─────────────────────────────────────────────────────── */

app.get("/api/snapshots", requireAuth, autoRegister, (req, res) => {
  res.json(stmtListSnapshots.all(req.user.oid, req.user.tenant));
});

app.post("/api/snapshots", requireAuth, autoRegister, (req, res) => {
  const label = (req.body?.label || "").trim();
  if (!label) return res.status(400).json({ error: "label is required" });

  let payload = req.body?.data;
  if (!payload || typeof payload !== "object") {
    const row = stmtGetAssessment.get(req.user.oid, req.user.tenant);
    if (!row) return res.status(404).json({ error: "No assessment to snapshot — save your assessment first" });
    try { payload = JSON.parse(row.data); } catch { return res.status(500).json({ error: "Corrupt assessment data" }); }
  }

  try {
    const result = stmtInsertSnapshot.run(req.user.oid, req.user.tenant, label, JSON.stringify(payload));
    res.status(201).json({ id: result.lastInsertRowid, label, created_at: Math.floor(Date.now() / 1000) });
  } catch (err) {
    console.error("[AESCSF API] Snapshot insert error:", err);
    res.status(500).json({ error: "Failed to save snapshot" });
  }
});

app.get("/api/snapshots/:id", requireAuth, autoRegister, (req, res) => {
  const row = stmtGetSnapshot.get(req.params.id, req.user.oid, req.user.tenant);
  if (!row) return res.status(404).json({ error: "Snapshot not found" });
  try {
    const parsed = JSON.parse(row.data);
    res.json({ id: row.id, label: row.label, created_at: row.created_at, ...parsed });
  } catch {
    res.status(500).json({ error: "Corrupt snapshot data" });
  }
});

app.delete("/api/snapshots/:id", requireAuth, autoRegister, (req, res) => {
  const info = stmtDeleteSnapshot.run(req.params.id, req.user.oid, req.user.tenant);
  if (info.changes === 0) return res.status(404).json({ error: "Snapshot not found" });
  res.json({ deleted: true });
});

/* ── Audit log routes ────────────────────────────────────────────────────── */

/**
 * GET /api/audit
 * Query params: practice_id, field, from (unix epoch), to, limit (max 500), offset
 * Admin: all users' entries. User: only their own entries.
 */
app.get("/api/audit", requireAuth, autoRegister, (req, res) => {
  const isAdmin = req.dbUser.role === "admin";
  const filters = {
    userOid:    isAdmin ? (req.query.user_oid || null) : req.user.oid,
    practiceId: req.query.practice_id || null,
    field:      req.query.field       || null,
    from:       req.query.from        ? parseInt(req.query.from)  : null,
    to:         req.query.to          ? parseInt(req.query.to)    : null,
    limit:      req.query.limit,
    offset:     req.query.offset,
  };
  try {
    res.json(queryAudit(filters));
  } catch (err) {
    console.error("[AESCSF API] Audit query error:", err);
    res.status(500).json({ error: "Failed to query audit log" });
  }
});

/**
 * GET /api/audit/export
 * Downloads the full audit log as a CSV file.
 * Admin: all entries. User: only their own entries.
 */
app.get("/api/audit/export", requireAuth, autoRegister, (req, res) => {
  const isAdmin = req.dbUser.role === "admin";
  const filters = {
    userOid:    isAdmin ? null : req.user.oid,
    practiceId: req.query.practice_id || null,
    field:      req.query.field       || null,
    from:       req.query.from ? parseInt(req.query.from) : null,
    to:         req.query.to   ? parseInt(req.query.to)   : null,
    limit:      10000,
    offset:     0,
  };
  try {
    const { rows } = queryAudit(filters);
    const dateStamp = new Date().toISOString().slice(0, 10);
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="aescsf-audit-${dateStamp}.csv"`);
    res.send(auditToCsv(rows));
  } catch (err) {
    console.error("[AESCSF API] Audit export error:", err);
    res.status(500).json({ error: "Failed to export audit log" });
  }
});

/**
 * GET /api/audit/practice/:id
 * Change history for a single practice.
 * Admin: all users' changes. User: only their own changes.
 */
app.get("/api/audit/practice/:id", requireAuth, autoRegister, (req, res) => {
  const isAdmin = req.dbUser.role === "admin";
  const filters = {
    practiceId: req.params.id,
    userOid:    isAdmin ? null : req.user.oid,
    limit:      200,
    offset:     0,
  };
  try {
    const { rows } = queryAudit(filters);
    res.json(rows);
  } catch (err) {
    console.error("[AESCSF API] Audit practice query error:", err);
    res.status(500).json({ error: "Failed to query practice history" });
  }
});

/* ── Evidence file routes ────────────────────────────────────────────────── */

/**
 * POST /api/files/:practiceId
 * Upload a single evidence file for a practice.
 * Multipart field name: "file"
 */
app.post("/api/files/:practiceId", requireAuth, autoRegister, (req, res, next) => {
  /* Run multer inside the route handler so we can send a clean JSON error */
  upload.single("file")(req, res, (err) => {
    if (err) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({ error: `File exceeds the ${MAX_FILE_BYTES / 1024 / 1024} MB limit` });
      }
      if (err.code === "INVALID_MIME") {
        return res.status(415).json({ error: err.message });
      }
      return next(err);
    }

    if (!req.file) return res.status(400).json({ error: "No file uploaded (field name must be 'file')" });

    try {
      const result = stmtInsertFile.run(
        req.user.oid,
        req.params.practiceId,
        req.file.originalname,
        req.file.filename,
        req.file.mimetype,
        req.file.size
      );
      res.status(201).json({
        id:          result.lastInsertRowid,
        practice_id: req.params.practiceId,
        filename:    req.file.originalname,
        mime_type:   req.file.mimetype,
        size_bytes:  req.file.size,
        uploaded_at: Math.floor(Date.now() / 1000)
      });
    } catch (dbErr) {
      /* Clean up the uploaded file if DB insert fails */
      fs.unlink(path.join(UPLOAD_DIR, req.file.filename), () => {});
      console.error("[AESCSF API] File DB insert error:", dbErr);
      res.status(500).json({ error: "Failed to record uploaded file" });
    }
  });
});

/**
 * GET /api/files/:practiceId
 * List all evidence files for a practice.
 * Admin: files from all users. User: only their own files.
 */
app.get("/api/files/:practiceId", requireAuth, autoRegister, (req, res) => {
  const isAdmin = req.dbUser.role === "admin";
  try {
    const files = listFilesForPractice(req.params.practiceId, req.user.oid, isAdmin);
    res.json(files);
  } catch (err) {
    console.error("[AESCSF API] File list error:", err);
    res.status(500).json({ error: "Failed to list files" });
  }
});

/**
 * GET /api/files/:id/download
 * Download a specific evidence file.
 * Users can only download their own files; admins can download any file.
 */
app.get("/api/files/:id/download", requireAuth, autoRegister, (req, res) => {
  const file = stmtGetFileById.get(req.params.id);
  if (!file) return res.status(404).json({ error: "File not found" });

  const isAdmin = req.dbUser.role === "admin";
  if (!isAdmin && file.user_oid !== req.user.oid) {
    return res.status(403).json({ error: "Access denied" });
  }

  const filePath = path.join(UPLOAD_DIR, file.stored_name);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "File not found on disk" });
  }

  res.setHeader("Content-Disposition", `attachment; filename="${file.filename.replace(/"/g, '\\"')}"`);
  res.setHeader("Content-Type", file.mime_type || "application/octet-stream");
  res.sendFile(filePath);
});

/**
 * DELETE /api/files/:id
 * Delete an evidence file.
 * Users can only delete their own files; admins can delete any file.
 */
app.delete("/api/files/:id", requireAuth, autoRegister, (req, res) => {
  const file = stmtGetFileById.get(req.params.id);
  if (!file) return res.status(404).json({ error: "File not found" });

  const isAdmin = req.dbUser.role === "admin";
  if (!isAdmin && file.user_oid !== req.user.oid) {
    return res.status(403).json({ error: "Access denied" });
  }

  stmtDeleteFileRecord.run(file.id);
  fs.unlink(path.join(UPLOAD_DIR, file.stored_name), (err) => {
    if (err) console.warn("[AESCSF API] Could not delete file from disk:", err.message);
  });
  res.json({ deleted: true });
});

/* ── Start ───────────────────────────────────────────────────────────────── */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[AESCSF API] Listening on port ${PORT}`);
  console.log(`[AESCSF API] SSO: ${SSO_ENABLED ? "EntraID (oauth2-proxy)" : "DISABLED"}`);
  console.log(`[AESCSF API] Admin OIDs: ${ADMIN_OIDS.length ? ADMIN_OIDS.join(", ") : "(first user will become admin)"}`);
  console.log(`[AESCSF API] DB:      ${path.join(DATA_DIR, "aescsf.db")}`);
  console.log(`[AESCSF API] Uploads: ${UPLOAD_DIR}`);
});
