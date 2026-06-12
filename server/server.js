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

const express   = require("express");
const helmet    = require("helmet");
const cors      = require("cors");
const rateLimit = require("express-rate-limit");
const morgan    = require("morgan");
const Database  = require("better-sqlite3");
const multer    = require("multer");
const path      = require("path");
const fs        = require("fs");
const crypto    = require("crypto");

/* ── Config ─────────────────────────────────────────────────────────────── */
const SSO_ENABLED   = process.env.AESCSF_SSO_ENABLED !== "false"; // default true
const PORT          = parseInt(process.env.PORT || "3000", 10);
const DATA_DIR      = process.env.DATA_DIR || "/data";
const UPLOAD_DIR    = path.join(DATA_DIR, "files");
const ADMIN_OIDS    = (process.env.AESCSF_ADMIN_OIDS || "")
                        .split(",").map(s => s.trim()).filter(Boolean);
const MAX_FILE_BYTES = 20 * 1024 * 1024; // 20 MB per file (multer limit)
// JSON body limit for assessment data (express.json). File uploads bypass this
// and are gated by MAX_FILE_BYTES above. nginx's client_max_body_size (25m) is
// the outermost gate — see docker-compose.yml api service comment for details.
const MAX_JSON_BYTES = "4mb";
const MAX_AUDIT_VALUE_LEN    = 4000; // truncate long field values in audit log
// Set to 0 to keep audit logs forever.
const AUDIT_RETENTION_DAYS   = parseInt(process.env.AESCSF_AUDIT_RETENTION_DAYS || "365", 10);

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

  CREATE TABLE IF NOT EXISTS objective_assignments (
    user_oid     TEXT    NOT NULL REFERENCES users(oid) ON DELETE CASCADE,
    objective_id TEXT    NOT NULL,
    assigned_by  TEXT    NOT NULL DEFAULT '',
    assigned_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (user_oid, objective_id)
  );
  CREATE INDEX IF NOT EXISTS idx_obj_assign_user ON objective_assignments(user_oid);
  CREATE TABLE IF NOT EXISTS confidence_ratings (
    practice_id  TEXT    NOT NULL,
    tenant_id    TEXT    NOT NULL DEFAULT '',
    rating       INTEGER NOT NULL DEFAULT 0,
    notes        TEXT    NOT NULL DEFAULT '',
    set_by_oid   TEXT    NOT NULL DEFAULT '',
    updated_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (practice_id, tenant_id)
  );
  CREATE TABLE IF NOT EXISTS approved_assessments (
    tenant_id  TEXT    NOT NULL PRIMARY KEY,
    data       TEXT    NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_by TEXT    NOT NULL DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS practice_versions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    practice_id  TEXT    NOT NULL,
    user_oid     TEXT    NOT NULL,
    display_name TEXT    NOT NULL DEFAULT '',
    tenant_id    TEXT    NOT NULL DEFAULT '',
    data         TEXT    NOT NULL,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_pv_practice ON practice_versions(practice_id, tenant_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_pv_user     ON practice_versions(user_oid, tenant_id);

  CREATE TABLE IF NOT EXISTS endorsements (
    practice_id  TEXT    NOT NULL,
    tenant_id    TEXT    NOT NULL DEFAULT '',
    version_id   INTEGER NOT NULL,
    endorsed_by  TEXT    NOT NULL DEFAULT '',
    endorsed_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (practice_id, tenant_id)
  );

  CREATE TABLE IF NOT EXISTS group_endorsements (
    practice_id TEXT    NOT NULL,
    group_id    INTEGER NOT NULL,
    tenant_id   TEXT    NOT NULL DEFAULT '',
    snapshot    TEXT    NOT NULL DEFAULT '{}',
    endorsed_by TEXT    NOT NULL DEFAULT '',
    endorsed_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (practice_id, group_id, tenant_id)
  );

  CREATE TABLE IF NOT EXISTS domain_targets (
    tenant_id   TEXT    NOT NULL DEFAULT '',
    domain      TEXT    NOT NULL,
    target_date TEXT    NOT NULL DEFAULT '',
    updated_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_by  TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, domain)
  );

  CREATE TABLE IF NOT EXISTS groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT    NOT NULL DEFAULT '',
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    created_by  TEXT    NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS idx_groups_tenant ON groups(tenant_id);

  CREATE TABLE IF NOT EXISTS group_members (
    group_id  INTEGER NOT NULL,
    user_oid  TEXT    NOT NULL,
    tenant_id TEXT    NOT NULL DEFAULT '',
    added_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    added_by  TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (group_id, user_oid)
  );
  CREATE INDEX IF NOT EXISTS idx_gm_group ON group_members(group_id);
  CREATE INDEX IF NOT EXISTS idx_gm_user  ON group_members(user_oid, tenant_id);

  CREATE TABLE IF NOT EXISTS group_domain_assignments (
    group_id  INTEGER NOT NULL,
    domain    TEXT    NOT NULL,
    tenant_id TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (group_id, domain)
  );

  CREATE TABLE IF NOT EXISTS group_objective_assignments (
    group_id     INTEGER NOT NULL,
    objective_id TEXT    NOT NULL,
    tenant_id    TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (group_id, objective_id)
  );

  CREATE TABLE IF NOT EXISTS group_targets (
    group_id    INTEGER NOT NULL,
    tenant_id   TEXT    NOT NULL DEFAULT '',
    target_key  TEXT    NOT NULL,
    target_date TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (group_id, target_key)
  );

  CREATE TABLE IF NOT EXISTS tenant_settings (
    tenant_id TEXT NOT NULL,
    key       TEXT NOT NULL,
    value     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, key)
  );
`);

/* Migration: add scope column to snapshots if it doesn't exist yet */
try { db.exec(`ALTER TABLE snapshots ADD COLUMN scope TEXT NOT NULL DEFAULT 'personal'`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_snapshots_golden ON snapshots(tenant_id, scope)`); } catch {}

/* Migration: expand users role constraint from 2 to 4 values */
try {
  const userTableSQL = db.prepare(
    "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'"
  ).get()?.sql || "";
  if (!userTableSQL.includes("assessor")) {
    /* Create users_v2 with new constraint, copy data, drop old, rename.
       We avoid renaming the existing 'users' table to prevent SQLite 3.26+
       from rewriting foreign-key references in other tables (assignments). */
    db.exec(`PRAGMA foreign_keys = OFF`);
    db.exec(`DROP TABLE IF EXISTS _users_v2`);
    db.exec(`
      CREATE TABLE _users_v2 (
        oid          TEXT    PRIMARY KEY,
        tenant_id    TEXT    NOT NULL DEFAULT '',
        username     TEXT    NOT NULL DEFAULT '',
        display_name TEXT    NOT NULL DEFAULT '',
        role         TEXT    NOT NULL DEFAULT 'user'
                             CHECK(role IN ('admin','user','assessor','dashboard')),
        created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
        last_seen    INTEGER NOT NULL DEFAULT (unixepoch())
      )
    `);
    db.exec(`INSERT INTO _users_v2 SELECT * FROM users`);
    db.exec(`DROP TABLE users`);
    db.exec(`ALTER TABLE _users_v2 RENAME TO users`);
    db.exec(`PRAGMA foreign_keys = ON`);
    console.log("[AESCSF API] Migrated users table to 4-role schema");
  }
} catch (e) { console.error("[AESCSF API] Role migration failed:", e.message); }

/* Migration: repair FK references broken by earlier rename-based migration */
try {
  const asgnDDL = db.prepare(
    "SELECT sql FROM sqlite_master WHERE type='table' AND name='assignments'"
  ).get()?.sql || "";
  if (asgnDDL.includes("_users_old")) {
    db.exec(`PRAGMA foreign_keys = OFF`);
    db.exec(`CREATE TABLE _asgn_tmp AS SELECT * FROM assignments`);
    db.exec(`DROP TABLE assignments`);
    db.exec(`
      CREATE TABLE assignments (
        user_oid    TEXT    NOT NULL REFERENCES users(oid) ON DELETE CASCADE,
        domain      TEXT    NOT NULL,
        assigned_by TEXT    NOT NULL DEFAULT '',
        assigned_at INTEGER NOT NULL DEFAULT (unixepoch()),
        PRIMARY KEY (user_oid, domain)
      )
    `);
    db.exec(`INSERT OR IGNORE INTO assignments SELECT * FROM _asgn_tmp`);
    db.exec(`DROP TABLE _asgn_tmp`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_assignments_user ON assignments(user_oid)`);

    db.exec(`CREATE TABLE _oasgn_tmp AS SELECT * FROM objective_assignments`);
    db.exec(`DROP TABLE objective_assignments`);
    db.exec(`
      CREATE TABLE objective_assignments (
        user_oid     TEXT    NOT NULL REFERENCES users(oid) ON DELETE CASCADE,
        objective_id TEXT    NOT NULL,
        assigned_by  TEXT    NOT NULL DEFAULT '',
        assigned_at  INTEGER NOT NULL DEFAULT (unixepoch()),
        PRIMARY KEY (user_oid, objective_id)
      )
    `);
    db.exec(`INSERT OR IGNORE INTO objective_assignments SELECT * FROM _oasgn_tmp`);
    db.exec(`DROP TABLE _oasgn_tmp`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_obj_assign_user ON objective_assignments(user_oid)`);
    db.exec(`DROP TABLE IF EXISTS _users_old`);
    db.exec(`PRAGMA foreign_keys = ON`);
    console.log("[AESCSF API] Repaired FK references in assignments tables");
  }
} catch (e) { console.error("[AESCSF API] FK repair failed:", e.message); }

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

/* Golden (shared) snapshots — tenant-scoped, admin-write, all-read */
const stmtListGoldenSnapshots = db.prepare(
  "SELECT id, label, created_at FROM snapshots WHERE tenant_id = ? AND scope = 'golden' ORDER BY created_at DESC"
);
const stmtGetGoldenSnapshot = db.prepare(
  "SELECT id, label, data, created_at FROM snapshots WHERE id = ? AND tenant_id = ? AND scope = 'golden'"
);
const stmtInsertGoldenSnapshot = db.prepare(
  "INSERT INTO snapshots (user_oid, tenant_id, label, data, scope) VALUES (?, ?, ?, ?, 'golden')"
);
const stmtDeleteGoldenSnapshot = db.prepare(
  "DELETE FROM snapshots WHERE id = ? AND tenant_id = ? AND scope = 'golden'"
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
const stmtGetObjectiveAssignments = db.prepare(
  "SELECT objective_id FROM objective_assignments WHERE user_oid = ? ORDER BY objective_id"
);
const stmtGetAllObjectiveAssignments = db.prepare(
  "SELECT user_oid, objective_id FROM objective_assignments ORDER BY user_oid, objective_id"
);
const stmtDeleteObjectiveAssignments = db.prepare(
  "DELETE FROM objective_assignments WHERE user_oid = ?"
);
const stmtInsertObjectiveAssignment = db.prepare(
  "INSERT OR REPLACE INTO objective_assignments (user_oid, objective_id, assigned_by, assigned_at) VALUES (?, ?, ?, unixepoch())"
);
const stmtGetApproved = db.prepare(
  "SELECT data FROM approved_assessments WHERE tenant_id = ?"
);
const stmtUpsertApproved = db.prepare(`
  INSERT INTO approved_assessments (tenant_id, data, updated_at, updated_by)
  VALUES (?, ?, unixepoch(), ?)
  ON CONFLICT(tenant_id) DO UPDATE SET
    data       = excluded.data,
    updated_at = excluded.updated_at,
    updated_by = excluded.updated_by
`);

/* Practice versions & endorsements */
const stmtInsertPracticeVersion = db.prepare(
  "INSERT INTO practice_versions (practice_id, user_oid, display_name, tenant_id, data) VALUES (?, ?, ?, ?, ?)"
);
const stmtGetPracticeVersions = db.prepare(`
  SELECT pv.id, pv.practice_id, pv.user_oid, pv.display_name, pv.created_at, pv.data,
         CASE WHEN e.version_id = pv.id THEN 1 ELSE 0 END AS is_endorsed
  FROM   practice_versions pv
  LEFT   JOIN endorsements e ON e.practice_id = pv.practice_id AND e.tenant_id = pv.tenant_id
  WHERE  pv.practice_id = ? AND pv.tenant_id = ?
  ORDER  BY pv.created_at DESC LIMIT 100
`);
const stmtGetAllEndorsements = db.prepare(`
  SELECT e.practice_id, e.version_id, e.endorsed_by, e.endorsed_at, pv.data,
         (SELECT COUNT(*) FROM practice_versions x
          WHERE x.practice_id = e.practice_id AND x.tenant_id = e.tenant_id AND x.id > e.version_id) AS changed_since
  FROM   endorsements e
  JOIN   practice_versions pv ON pv.id = e.version_id
  WHERE  e.tenant_id = ?
`);
const stmtUpsertEndorsement = db.prepare(`
  INSERT INTO endorsements (practice_id, tenant_id, version_id, endorsed_by, endorsed_at)
  VALUES (?, ?, ?, ?, unixepoch())
  ON CONFLICT(practice_id, tenant_id) DO UPDATE SET
    version_id  = excluded.version_id,
    endorsed_by = excluded.endorsed_by,
    endorsed_at = excluded.endorsed_at
`);
const stmtDeleteEndorsement = db.prepare(
  "DELETE FROM endorsements WHERE practice_id = ? AND tenant_id = ?"
);
const stmtVerifyVersion = db.prepare(
  "SELECT id FROM practice_versions WHERE id = ? AND tenant_id = ? AND practice_id = ?"
);

const stmtGetDomainTargets = db.prepare(
  "SELECT domain, target_date FROM domain_targets WHERE tenant_id = ? ORDER BY domain"
);
const stmtUpsertDomainTarget = db.prepare(`
  INSERT INTO domain_targets (tenant_id, domain, target_date, updated_at, updated_by)
  VALUES (?, ?, ?, unixepoch(), ?)
  ON CONFLICT(tenant_id, domain) DO UPDATE SET
    target_date = excluded.target_date,
    updated_at  = excluded.updated_at,
    updated_by  = excluded.updated_by
`);
const stmtDeleteDomainTarget = db.prepare(
  "DELETE FROM domain_targets WHERE tenant_id = ? AND domain = ?"
);

/* Groups */
const stmtListGroups = db.prepare(
  "SELECT id, name, description, created_at FROM groups WHERE tenant_id = ? ORDER BY name"
);
const stmtGetGroup = db.prepare(
  "SELECT id, name, description, created_at, created_by FROM groups WHERE id = ? AND tenant_id = ?"
);
const stmtInsertGroup = db.prepare(
  "INSERT INTO groups (tenant_id, name, description, created_by) VALUES (?, ?, ?, ?)"
);
const stmtUpdateGroup = db.prepare(
  "UPDATE groups SET name = ?, description = ? WHERE id = ? AND tenant_id = ?"
);
const stmtDeleteGroup = db.prepare(
  "DELETE FROM groups WHERE id = ? AND tenant_id = ?"
);
const stmtGetGroupMembers = db.prepare(`
  SELECT gm.user_oid AS oid, u.display_name, u.username, u.role
  FROM group_members gm
  LEFT JOIN users u ON gm.user_oid = u.oid
  WHERE gm.group_id = ?
  ORDER BY u.display_name
`);
const stmtClearGroupMembers = db.prepare(
  "DELETE FROM group_members WHERE group_id = ?"
);
const stmtInsertGroupMember = db.prepare(
  "INSERT OR IGNORE INTO group_members (group_id, user_oid, tenant_id, added_by) VALUES (?, ?, ?, ?)"
);
const stmtRemoveUserFromAllGroups = db.prepare(
  "DELETE FROM group_members WHERE user_oid = ? AND tenant_id = ?"
);
const stmtGetGroupDomains = db.prepare(
  "SELECT domain FROM group_domain_assignments WHERE group_id = ? ORDER BY domain"
);
const stmtClearGroupDomains = db.prepare(
  "DELETE FROM group_domain_assignments WHERE group_id = ?"
);
const stmtInsertGroupDomain = db.prepare(
  "INSERT OR IGNORE INTO group_domain_assignments (group_id, domain, tenant_id) VALUES (?, ?, ?)"
);
const stmtGetGroupObjectives = db.prepare(
  "SELECT objective_id FROM group_objective_assignments WHERE group_id = ? ORDER BY objective_id"
);
const stmtClearGroupObjectives = db.prepare(
  "DELETE FROM group_objective_assignments WHERE group_id = ?"
);
const stmtInsertGroupObjective = db.prepare(
  "INSERT OR IGNORE INTO group_objective_assignments (group_id, objective_id, tenant_id) VALUES (?, ?, ?)"
);
const stmtGetGroupDomainsByUser = db.prepare(`
  SELECT DISTINCT gda.domain
  FROM group_members gm
  JOIN group_domain_assignments gda ON gm.group_id = gda.group_id
  WHERE gm.user_oid = ?
`);
const stmtGetGroupObjectivesByUser = db.prepare(`
  SELECT DISTINCT goa.objective_id
  FROM group_members gm
  JOIN group_objective_assignments goa ON gm.group_id = goa.group_id
  WHERE gm.user_oid = ?
`);
const stmtGetUserGroups = db.prepare(`
  SELECT g.id, g.name
  FROM groups g
  JOIN group_members gm ON g.id = gm.group_id
  WHERE gm.user_oid = ? AND g.tenant_id = ?
  ORDER BY g.name
`);
const stmtGetGroupTargets   = db.prepare("SELECT target_key, target_date FROM group_targets WHERE group_id = ? AND tenant_id = ?");
const stmtClearGroupTargets = db.prepare("DELETE FROM group_targets WHERE group_id = ? AND tenant_id = ?");
const stmtInsertGroupTarget = db.prepare("INSERT OR REPLACE INTO group_targets (group_id, tenant_id, target_key, target_date) VALUES (?, ?, ?, ?)");
const stmtGetGroupMemberCount = db.prepare(
  "SELECT COUNT(*) AS n FROM group_members WHERE group_id = ?"
);
const stmtGetGroupEndorsements = db.prepare(
  "SELECT practice_id, group_id, snapshot, endorsed_by, endorsed_at FROM group_endorsements WHERE tenant_id = ?"
);
const stmtUpsertGroupEndorsement = db.prepare(`
  INSERT INTO group_endorsements (practice_id, group_id, tenant_id, snapshot, endorsed_by, endorsed_at)
  VALUES (?, ?, ?, ?, ?, unixepoch())
  ON CONFLICT(practice_id, group_id, tenant_id) DO UPDATE SET
    snapshot    = excluded.snapshot,
    endorsed_by = excluded.endorsed_by,
    endorsed_at = excluded.endorsed_at
`);

const stmtGetAllConfidence = db.prepare(
  "SELECT practice_id, rating, notes, updated_at FROM confidence_ratings WHERE tenant_id = ?"
);
const stmtUpsertConfidence = db.prepare(`
  INSERT INTO confidence_ratings (practice_id, tenant_id, rating, notes, set_by_oid, updated_at)
  VALUES (?, ?, ?, ?, ?, unixepoch())
  ON CONFLICT(practice_id, tenant_id) DO UPDATE SET
    rating     = excluded.rating,
    notes      = excluded.notes,
    set_by_oid = excluded.set_by_oid,
    updated_at = unixepoch()
`);

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

function requireAdminOrAssessor(req, res, next) {
  if (!req.dbUser || !["admin", "assessor"].includes(req.dbUser.role)) {
    return res.status(403).json({ error: "Admin or assessor access required" });
  }
  next();
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */
// Domains whose name contains a hyphen — split("-")[0] would give the wrong result
const HYPHENATED_DOMAINS = ["THIRD-PARTIES"];
function practiceDomain(practiceId) {
  const upper = practiceId.toUpperCase();
  for (const d of HYPHENATED_DOMAINS) {
    if (upper.startsWith(d + "-")) return d;
  }
  return upper.split("-")[0];
}

function practiceObjectiveId(practiceId) {
  return practiceId
    .replace(/-\d+$/, '')
    .replace(/[a-z]$/, '');
}

function getUserObjectiveAssignments(oid) {
  return stmtGetGroupObjectivesByUser.all(oid).map(r => r.objective_id);
}

function getUserAssignments(oid) {
  return stmtGetGroupDomainsByUser.all(oid).map(r => r.domain);
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

  // Build contributors map: { [practiceId]: [{ user_oid, display_name, username, assessment }] }
  const usersByOid = {};
  for (const u of stmtGetAllUsers.all()) usersByOid[u.oid] = u;
  const contributors = {};
  for (const row of allRows) {
    const assessments = assessmentsByOid[row.user_oid]?.assessments || {};
    const u = usersByOid[row.user_oid] || {};
    for (const [practiceId, assessment] of Object.entries(assessments)) {
      const s = assessment?.status || "";
      const hasData = s && s !== "Not Assessed" || assessment?.evidence || assessment?.gap || assessment?.notes;
      if (!hasData) continue;
      if (!contributors[practiceId]) contributors[practiceId] = [];
      contributors[practiceId].push({
        user_oid:     row.user_oid,
        display_name: u.display_name || row.user_oid,
        username:     u.username     || row.user_oid,
        assessment
      });
    }
  }
  return { assessments: merged, _mergedView: true, _contributors: contributors };
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

/** Record a practice_versions row for each practice whose audited fields changed. */
function insertPracticeVersions(userOid, displayName, tenant, oldData, newData) {
  const oldAssessments = oldData?.assessments || {};
  const newAssessments = newData?.assessments || {};
  for (const [practiceId, newP] of Object.entries(newAssessments)) {
    const oldP = oldAssessments[practiceId] || {};
    const changed = AUDITED_FIELDS.some(
      f => String(newP[f] ?? "").trim() !== String(oldP[f] ?? "").trim()
    );
    if (changed) {
      stmtInsertPracticeVersion.run(practiceId, userOid, displayName, tenant, JSON.stringify(newP));
    }
  }
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

/* ── Audit log retention ─────────────────────────────────────────────────── */
const stmtPurgeAudit = AUDIT_RETENTION_DAYS > 0
  ? db.prepare("DELETE FROM audit_log WHERE created_at < unixepoch() - ?")
  : null;

function purgeAuditLog() {
  if (!stmtPurgeAudit) return { deleted: 0, retentionDays: 0 };
  const cutoffSeconds = AUDIT_RETENTION_DAYS * 86400;
  const { changes } = stmtPurgeAudit.run(cutoffSeconds);
  if (changes > 0) {
    console.log(`[AESCSF] Audit log purge: removed ${changes} entr${changes === 1 ? "y" : "ies"} older than ${AUDIT_RETENTION_DAYS} days`);
  }
  return { deleted: changes, retentionDays: AUDIT_RETENTION_DAYS };
}

// Purge on startup, then once every 24 hours.
purgeAuditLog();
setInterval(purgeAuditLog, 24 * 60 * 60 * 1000).unref();

/* ── Express app ─────────────────────────────────────────────────────────── */
const app = express();

app.use(morgan("combined"));
app.use(helmet({ contentSecurityPolicy: false })); // CSP set by nginx instead
app.use(cors({
  origin:  process.env.ALLOWED_ORIGIN || false,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: MAX_JSON_BYTES }));

// ── Rate limiting ─────────────────────────────────────────────────────────────
// The API is only reachable from nginx (internal Docker network), so the
// X-Forwarded-For header from nginx is trustworthy for per-IP limiting.
app.set("trust proxy", 1);

// General limit: 300 requests per 15 minutes per IP
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests — please try again later." }
});

// Tighter limit for bulk-export endpoints (10 per 15 minutes per IP)
const exportLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Export rate limit exceeded — please try again later." }
});

app.use(generalLimiter);

/* ── Routes ─────────────────────────────────────────────────────────────── */

app.get("/api/health", (_req, res) => {
  try {
    db.prepare("SELECT 1").get();
    res.json({ status: "ok", db: "ok", sso: SSO_ENABLED, ts: Date.now() });
  } catch (err) {
    console.error("[AESCSF API] Health check — DB error:", err.message);
    res.status(503).json({ status: "error", db: "unavailable", sso: SSO_ENABLED });
  }
});

app.get("/api/me", requireAuth, autoRegister, (req, res) => {
  const domains    = getUserAssignments(req.user.oid);
  const objectives = getUserObjectiveAssignments(req.user.oid);
  const groups     = stmtGetUserGroups.all(req.user.oid, req.user.tenant)
    .map(g => ({ id: g.id, name: g.name }));
  res.json({
    oid:         req.dbUser.oid,
    username:    req.dbUser.username,
    displayName: req.dbUser.display_name,
    role:        req.dbUser.role,
    domains,
    objectives,
    groups
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

  if (req.dbUser.role === "dashboard") {
    return res.status(403).json({ error: "Read-only access" });
  }
  const isAdmin = req.dbUser.role === "admin" || req.dbUser.role === "assessor";
  let payload   = req.body;

  if (!isAdmin) {
    const allowedDomains    = new Set(getUserAssignments(req.user.oid));
    const allowedObjectives = new Set(getUserObjectiveAssignments(req.user.oid));
    if (payload.assessments) {
      const filtered = {};
      for (const [practiceId, data] of Object.entries(payload.assessments)) {
        const pDomain    = practiceDomain(practiceId);
        const pObjective = practiceObjectiveId(practiceId);
        if (allowedDomains.has(pDomain) || allowedObjectives.has(pObjective)) {
          filtered[practiceId] = data;
        }
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

  /* Write audit log entries and practice versions for any changed fields (best-effort) */
  try {
    const displayName = req.dbUser?.display_name || req.user.username || "";
    const changes = diffAndLog(req.user, oldData, payload);
    insertPracticeVersions(req.user.oid, displayName, req.user.tenant, oldData, payload);
    res.json({ saved: true, changes });
  } catch (auditErr) {
    console.error("[AESCSF API] Audit log error (non-fatal):", auditErr);
    res.json({ saved: true, changes: 0 });
  }
});

/* ── Domain target dates ─────────────────────────────────────────────────── */

app.get("/api/domain-targets", requireAuth, autoRegister, (req, res) => {
  const rows = stmtGetDomainTargets.all(req.user.tenant);
  const targets = {};
  for (const row of rows) {
    if (row.target_date) targets[row.domain] = row.target_date;
  }
  res.json(targets);
});

app.put("/api/domain-targets", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const body = req.body;
  if (typeof body !== "object" || Array.isArray(body)) {
    return res.status(400).json({ error: "Body must be an object mapping domain to date string" });
  }
  const upsertTx = db.transaction(() => {
    for (const [domain, date] of Object.entries(body)) {
      if (!date || date.trim() === "") {
        stmtDeleteDomainTarget.run(req.user.tenant, domain);
      } else {
        stmtUpsertDomainTarget.run(req.user.tenant, domain, date.trim(), req.user.oid);
      }
    }
  });
  upsertTx();
  res.json({ ok: true });
});

/* ── Organisation goal ───────────────────────────────────────────────────── */

app.get("/api/admin/org-goal", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const row = db.prepare("SELECT value FROM tenant_settings WHERE tenant_id = ? AND key = 'org_goal'").get(req.user.tenant);
  res.json(row ? JSON.parse(row.value) : {});
});

app.put("/api/admin/org-goal", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const { goalName = "", targetSp = "", targetDate = "" } = req.body || {};
  const value = JSON.stringify({ goalName, targetSp, targetDate });
  db.prepare(`INSERT INTO tenant_settings (tenant_id, key, value) VALUES (?, 'org_goal', ?)
    ON CONFLICT(tenant_id, key) DO UPDATE SET value = excluded.value`).run(req.user.tenant, value);
  res.json({ ok: true });
});

/* ── Groups (Business Units) ─────────────────────────────────────────────── */

/* Lightweight user list for group management — accessible to admin + assessor */
app.get("/api/groups/users", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const users = db.prepare(`
    SELECT u.oid, u.username, u.display_name, u.role,
           g.id AS group_id, g.name AS group_name
    FROM users u
    LEFT JOIN group_members gm ON gm.user_oid = u.oid AND gm.tenant_id = u.tenant_id
    LEFT JOIN groups g ON g.id = gm.group_id
    WHERE u.tenant_id = ?
    ORDER BY u.display_name, u.username
  `).all(req.user.tenant);
  res.json(users);
});

app.get("/api/groups", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const groups = stmtListGroups.all(req.user.tenant);
  res.json(groups.map(g => ({
    ...g,
    memberCount: stmtGetGroupMemberCount.get(g.id)?.n || 0,
    domains:     stmtGetGroupDomains.all(g.id).map(r => r.domain),
    objectives:  stmtGetGroupObjectives.all(g.id).map(r => r.objective_id)
  })));
});

app.post("/api/groups", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const { name, description = "" } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Name is required" });
  const info = stmtInsertGroup.run(req.user.tenant, name.trim(), description.trim(), req.user.oid);
  res.json({ id: Number(info.lastInsertRowid), name: name.trim(), description: description.trim() });
});

app.get("/api/groups/:id", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const id    = parseInt(req.params.id);
  const group = stmtGetGroup.get(id, req.user.tenant);
  if (!group) return res.status(404).json({ error: "Group not found" });
  res.json({
    ...group,
    members:    stmtGetGroupMembers.all(id),
    domains:    stmtGetGroupDomains.all(id).map(r => r.domain),
    objectives: stmtGetGroupObjectives.all(id).map(r => r.objective_id)
  });
});

app.put("/api/groups/:id", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const id    = parseInt(req.params.id);
  const { name, description = "" } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "Name is required" });
  const info = stmtUpdateGroup.run(name.trim(), description.trim(), id, req.user.tenant);
  if (info.changes === 0) return res.status(404).json({ error: "Group not found" });
  res.json({ ok: true });
});

app.delete("/api/groups/:id", requireAuth, autoRegister, requireAdmin, (req, res) => {
  stmtDeleteGroup.run(parseInt(req.params.id), req.user.tenant);
  res.json({ ok: true });
});

app.put("/api/groups/:id/members", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const id    = parseInt(req.params.id);
  const group = stmtGetGroup.get(id, req.user.tenant);
  if (!group) return res.status(404).json({ error: "Group not found" });
  const oids = Array.isArray(req.body.members) ? req.body.members : [];
  db.transaction(() => {
    stmtClearGroupMembers.run(id);
    for (const oid of oids) {
      // Enforce one-to-one: remove user from any other group before adding here
      stmtRemoveUserFromAllGroups.run(oid, req.user.tenant);
      stmtInsertGroupMember.run(id, oid, req.user.tenant, req.user.oid);
    }
  })();
  res.json({ ok: true });
});

app.put("/api/groups/:id/domains", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const id    = parseInt(req.params.id);
  const group = stmtGetGroup.get(id, req.user.tenant);
  if (!group) return res.status(404).json({ error: "Group not found" });
  const domains = Array.isArray(req.body.domains) ? req.body.domains : [];
  db.transaction(() => {
    stmtClearGroupDomains.run(id);
    for (const d of domains) stmtInsertGroupDomain.run(id, d, req.user.tenant);
  })();
  res.json({ ok: true });
});

app.put("/api/groups/:id/objectives", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const id    = parseInt(req.params.id);
  const group = stmtGetGroup.get(id, req.user.tenant);
  if (!group) return res.status(404).json({ error: "Group not found" });
  const objectives = Array.isArray(req.body.objectives) ? req.body.objectives : [];
  db.transaction(() => {
    stmtClearGroupObjectives.run(id);
    for (const o of objectives) stmtInsertGroupObjective.run(id, o, req.user.tenant);
  })();
  res.json({ ok: true });
});

app.get("/api/groups/:id/targets", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const id    = parseInt(req.params.id);
  const group = stmtGetGroup.get(id, req.user.tenant);
  if (!group) return res.status(404).json({ error: "Group not found" });
  const rows    = stmtGetGroupTargets.all(id, req.user.tenant);
  const targets = Object.fromEntries(rows.map(r => [r.target_key, r.target_date]));
  res.json({ targets });
});

app.put("/api/groups/:id/targets", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const id    = parseInt(req.params.id);
  const group = stmtGetGroup.get(id, req.user.tenant);
  if (!group) return res.status(404).json({ error: "Group not found" });
  const targets = req.body.targets && typeof req.body.targets === "object" ? req.body.targets : {};
  db.transaction(() => {
    stmtClearGroupTargets.run(id, req.user.tenant);
    for (const [key, date] of Object.entries(targets)) {
      if (date && typeof date === "string") stmtInsertGroupTarget.run(id, req.user.tenant, key, date);
    }
  })();
  res.json({ ok: true });
});

app.get("/api/groups/:id/results", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  const id    = parseInt(req.params.id);
  const group = stmtGetGroup.get(id, req.user.tenant);
  if (!group) return res.status(404).json({ error: "Group not found" });
  const members = stmtGetGroupMembers.all(id);
  const memberAssessments = {};
  for (const m of members) {
    const row = stmtGetAssessment.get(m.oid, req.user.tenant);
    memberAssessments[m.oid] = {
      displayName: m.display_name || m.username || m.oid,
      data: row ? (JSON.parse(row.data)?.assessments || {}) : {}
    };
  }
  res.json({
    id:           group.id,
    name:         group.name,
    description:  group.description,
    members:      members.map(m => ({ oid: m.oid, displayName: m.display_name || m.username })),
    domains:      stmtGetGroupDomains.all(id).map(r => r.domain),
    objectives:   stmtGetGroupObjectives.all(id).map(r => r.objective_id),
    assessments:  memberAssessments
  });
});

/* ── Group multi-respondent & endorsement routes ─────────────────────────── */

const STATUS_PRIORITY = { "No": 0, "Partial": 1, "In Progress": 1, "Yes": 2, "Not Assessed": 3 };
function groupWorstCase(statuses) {
  return statuses.reduce((w, s) =>
    (STATUS_PRIORITY[s] ?? 3) < (STATUS_PRIORITY[w] ?? 3) ? s : w, "Not Assessed");
}

app.get("/api/admin/group-responses", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  try {
    const groups    = stmtListGroups.all(req.user.tenant);
    const groupById = Object.fromEntries(groups.map(g => [g.id, g]));

    // Load each group's domain/objective assignments
    const groupDomainSets = {};
    const groupObjSets    = {};
    const groupsMeta      = {};
    for (const g of groups) {
      const gDomains = stmtGetGroupDomains.all(g.id).map(r => r.domain);
      const gObjIds  = stmtGetGroupObjectives.all(g.id).map(r => r.objective_id);
      groupDomainSets[g.id] = new Set(gDomains);
      groupObjSets[g.id]    = new Set(gObjIds);
      groupsMeta[g.id]      = { name: g.name, domains: gDomains, objectives: gObjIds };
    }

    const userGroupMap = {};
    for (const g of groups) {
      for (const m of stmtGetGroupMembers.all(g.id)) userGroupMap[m.oid] = g.id;
    }

    const allUsers = db.prepare(
      "SELECT oid, username, display_name FROM users WHERE tenant_id = ?"
    ).all(req.user.tenant);
    const usersByOid = Object.fromEntries(allUsers.map(u => [u.oid, u]));

    const allRows = db.prepare(
      "SELECT user_oid, data FROM assessments WHERE tenant_id = ?"
    ).all(req.user.tenant);

    const byPractice = {};
    for (const row of allRows) {
      const user    = usersByOid[row.user_oid];
      const groupId = userGroupMap[row.user_oid];
      try {
        const assessments = JSON.parse(row.data)?.assessments || {};
        for (const [practiceId, assessment] of Object.entries(assessments)) {
          const pDomain  = practiceDomain(practiceId);
          const pObjId   = practiceObjectiveId(practiceId);
          const entry    = { user_oid: row.user_oid, display_name: user?.display_name || row.user_oid, username: user?.username || row.user_oid, assessment };
          if (groupId) {
            // Only include practices within the group's assigned domains/objectives
            if (!groupDomainSets[groupId]?.has(pDomain) && !groupObjSets[groupId]?.has(pObjId)) continue;
            if (!byPractice[practiceId]) byPractice[practiceId] = { groups: {}, ungrouped: [] };
            if (!byPractice[practiceId].groups[groupId]) byPractice[practiceId].groups[groupId] = [];
            byPractice[practiceId].groups[groupId].push(entry);
          } else {
            if (!byPractice[practiceId]) byPractice[practiceId] = { groups: {}, ungrouped: [] };
            byPractice[practiceId].ungrouped.push(entry);
          }
        }
      } catch { /* skip corrupt */ }
    }

    const result = { _groups_meta: groupsMeta };
    for (const [practiceId, { groups, ungrouped }] of Object.entries(byPractice)) {
      result[practiceId] = {
        groups: Object.entries(groups).map(([gid, members]) => ({
          group_id:         Number(gid),
          group_name:       groupById[gid]?.name || `Group ${gid}`,
          aggregate_status: groupWorstCase(members.map(m => m.assessment?.status || "Not Assessed")),
          members
        })).sort((a, b) => a.group_name.localeCompare(b.group_name)),
        ungrouped
      };
    }
    res.json(result);
  } catch (err) {
    console.error("[AESCSF API] Group responses error:", err);
    res.status(500).json({ error: "Failed to load group responses" });
  }
});

app.get("/api/admin/group-endorsements", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  try {
    const endorsements = stmtGetGroupEndorsements.all(req.user.tenant);
    const groups       = stmtListGroups.all(req.user.tenant);
    const userGroupMap = {};
    for (const g of groups) {
      for (const m of stmtGetGroupMembers.all(g.id)) userGroupMap[m.oid] = g.id;
    }

    const allRows = db.prepare(
      "SELECT user_oid, data FROM assessments WHERE tenant_id = ?"
    ).all(req.user.tenant);

    // Build current member-status snapshots per (practiceId, groupId)
    const currentState = {};
    for (const row of allRows) {
      const gid = userGroupMap[row.user_oid];
      if (!gid) continue;
      try {
        const assessments = JSON.parse(row.data)?.assessments || {};
        for (const [practiceId, a] of Object.entries(assessments)) {
          const key = `${practiceId}:${gid}`;
          if (!currentState[key]) currentState[key] = {};
          currentState[key][row.user_oid] = a?.status || "Not Assessed";
        }
      } catch { /* skip */ }
    }

    const result = {};
    for (const row of endorsements) {
      try {
        const snapshot     = JSON.parse(row.snapshot);
        const key          = `${row.practice_id}:${row.group_id}`;
        const current      = currentState[key] || {};
        const changed      = JSON.stringify(snapshot.member_statuses || {}) !== JSON.stringify(current);
        result[key] = {
          practice_id:   row.practice_id,
          group_id:      row.group_id,
          endorsed_by:   row.endorsed_by,
          endorsed_at:   row.endorsed_at,
          snapshot,
          changed_since: changed
        };
      } catch { /* skip */ }
    }
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Failed to load group endorsements" });
  }
});

app.post("/api/admin/groups/:groupId/endorse-responses", requireAuth, autoRegister, requireAdminOrAssessor, (req, res) => {
  try {
    const groupId = parseInt(req.params.groupId);
    const group   = stmtGetGroup.get(groupId, req.user.tenant);
    if (!group) return res.status(404).json({ error: "Group not found" });

    const practiceIds = Array.isArray(req.body.practiceIds) ? new Set(req.body.practiceIds) : null;
    const members     = stmtGetGroupMembers.all(groupId);

    const allRows = db.prepare(
      "SELECT user_oid, data FROM assessments WHERE tenant_id = ?"
    ).all(req.user.tenant);

    // Build snapshot: { [practiceId]: { member_statuses: { [oid]: status } } }
    const snapshots = {};
    for (const row of allRows) {
      if (!members.some(m => m.oid === row.user_oid)) continue;
      try {
        const assessments = JSON.parse(row.data)?.assessments || {};
        for (const [pid, a] of Object.entries(assessments)) {
          if (practiceIds && !practiceIds.has(pid)) continue;
          if (!snapshots[pid]) snapshots[pid] = { member_statuses: {} };
          snapshots[pid].member_statuses[row.user_oid] = a?.status || "Not Assessed";
        }
      } catch { /* skip */ }
    }

    const endorsedBy = req.dbUser.display_name || req.user.username;
    db.transaction(() => {
      for (const [pid, snapshot] of Object.entries(snapshots)) {
        stmtUpsertGroupEndorsement.run(pid, groupId, req.user.tenant, JSON.stringify(snapshot), endorsedBy);
      }
    })();

    res.json({ endorsed: Object.keys(snapshots).length, practiceIds: Object.keys(snapshots) });
  } catch (err) {
    console.error("[AESCSF API] Group endorse error:", err);
    res.status(500).json({ error: "Failed to endorse" });
  }
});

/* ── Admin routes ────────────────────────────────────────────────────────── */

app.get("/api/admin/users", requireAuth, autoRegister, requireAdmin, (req, res) => {
  const users = stmtGetAllUsers.all();

  // Group memberships (one group per user enforced at application layer)
  const allGroupMembers = db.prepare(`
    SELECT gm.user_oid, g.id AS group_id, g.name AS group_name
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id
    WHERE g.tenant_id = ?
  `).all(req.user.tenant);
  const groupsByOid = {};
  for (const gm of allGroupMembers) {
    if (!groupsByOid[gm.user_oid]) groupsByOid[gm.user_oid] = [];
    groupsByOid[gm.user_oid].push({ id: gm.group_id, name: gm.group_name });
  }

  res.json(users.map(u => ({
    ...u,
    groups:     groupsByOid[u.oid]           || [],
    domains:    getUserAssignments(u.oid),       // group-inherited only
    objectives: getUserObjectiveAssignments(u.oid)
  })));
});

app.put("/api/admin/users/:oid/role", requireAuth, autoRegister, requireAdmin, (req, res) => {
  const { role } = req.body || {};
  const VALID_ROLES = new Set(["admin", "user", "assessor", "dashboard"]);
  if (!VALID_ROLES.has(role)) {
    return res.status(400).json({ error: "role must be 'admin', 'user', 'assessor', or 'dashboard'" });
  }
  const target = stmtGetUser.get(req.params.oid);
  if (!target) return res.status(404).json({ error: "User not found" });

  const oldRole = target.role;
  stmtSetRole.run(role, req.params.oid);

  try {
    stmtInsertAudit.run(
      req.user.oid,
      req.user.username,
      req.dbUser.display_name,
      `USER:${target.username || target.oid}`,
      "role",
      oldRole,
      role
    );
  } catch (auditErr) {
    console.error("[AESCSF API] Admin audit log error (non-fatal):", auditErr);
  }

  res.json({ updated: true, oid: req.params.oid, role });
});

app.put("/api/admin/users/:oid/assignments", requireAuth, autoRegister, requireAdmin, (req, res) => {
  const { domains } = req.body || {};
  if (!Array.isArray(domains)) {
    return res.status(400).json({ error: "domains must be an array of strings" });
  }
  const target = stmtGetUser.get(req.params.oid);
  if (!target) return res.status(404).json({ error: "User not found" });

  const oldDomains = getUserAssignments(req.params.oid);

  const setAssignments = db.transaction((oid, domainList, byOid) => {
    stmtDeleteAssignments.run(oid);
    for (const domain of domainList) {
      stmtInsertAssignment.run(oid, domain.toUpperCase(), byOid);
    }
  });

  try {
    setAssignments(req.params.oid, domains, req.user.oid);

    const oldVal = oldDomains.slice().sort().join(", ") || "(none)";
    const newVal = domains.map(d => d.toUpperCase()).sort().join(", ") || "(none)";
    if (oldVal !== newVal) {
      try {
        stmtInsertAudit.run(
          req.user.oid,
          req.user.username,
          req.dbUser.display_name,
          `USER:${target.username || target.oid}`,
          "domain_assignments",
          oldVal,
          newVal
        );
      } catch (auditErr) {
        console.error("[AESCSF API] Admin audit log error (non-fatal):", auditErr);
      }
    }

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

app.get("/api/admin/assessment/approved", requireAuth, autoRegister, requireAdmin, (req, res) => {
  const row = stmtGetApproved.get(req.user.tenant);
  if (!row) return res.status(404).json({ error: "No approved assessment found" });
  try {
    res.json(JSON.parse(row.data));
  } catch (err) {
    res.status(500).json({ error: "Failed to parse approved assessment" });
  }
});

app.post("/api/admin/users/:oid/approve-contributions", requireAuth, autoRegister, requireAdmin, (req, res) => {
  const { practiceIds } = req.body || {};
  const target = stmtGetUser.get(req.params.oid);
  if (!target) return res.status(404).json({ error: "User not found" });

  const targetRow = stmtGetAssessment.get(req.params.oid, req.user.tenant);
  if (!targetRow) return res.status(404).json({ error: "No assessment found for this user" });
  const targetAssessments = (() => { try { return JSON.parse(targetRow.data)?.assessments || {}; } catch { return {}; } })();

  const approvedRow = stmtGetApproved.get(req.user.tenant);
  const approvedAssessments = (() => { try { return approvedRow ? JSON.parse(approvedRow.data)?.assessments || {} : {}; } catch { return {}; } })();

  // Determine scope: explicit practiceIds list OR all practices in user's assigned scope
  let toApprove;
  if (Array.isArray(practiceIds) && practiceIds.length) {
    toApprove = new Set(practiceIds);
  } else {
    const userDomains    = new Set(getUserAssignments(req.params.oid));
    const userObjectives = new Set(getUserObjectiveAssignments(req.params.oid));
    toApprove = new Set(
      Object.keys(targetAssessments).filter(pid => {
        if (!userDomains.size && !userObjectives.size) return true;
        const pDomain    = practiceDomain(pid);
        const pObjective = practiceObjectiveId(pid);
        return userDomains.has(pDomain) || userObjectives.has(pObjective);
      })
    );
  }

  let approvedCount = 0;
  for (const practiceId of toApprove) {
    if (targetAssessments[practiceId]) {
      approvedAssessments[practiceId] = { ...targetAssessments[practiceId] };
      approvedCount++;
    }
  }

  stmtUpsertApproved.run(req.user.tenant, JSON.stringify({ assessments: approvedAssessments, _approvedView: true }), req.user.oid);

  stmtInsertAudit.run(
    req.user.oid, req.user.username, req.dbUser.display_name,
    `USER:${target.username || req.params.oid}`, "contributions_approved",
    "", `${approvedCount} practices approved`
  );

  res.json({ approved: approvedCount, userOid: req.params.oid });
});

/**
 * POST /api/admin/users/:oid/endorse-contributions
 * Endorses the latest saved version of each practice for a given user.
 * If no practice_versions record exists (data saved before versioning was deployed),
 * a version is created on-the-fly from the user's current assessment data so the
 * endorsement always succeeds.
 * Body: { practiceIds: ["ACCESS-1a", ...] } — omit to endorse all practices the user has saved.
 * Admin only.
 */
app.post("/api/admin/users/:oid/endorse-contributions", requireAuth, autoRegister, requireAdmin, (req, res) => {
  try {
    const { practiceIds } = req.body || {};
    const target = stmtGetUser.get(req.params.oid);
    if (!target) return res.status(404).json({ error: "User not found" });

    const endorsedBy  = req.dbUser.display_name || req.user.username || "";
    const displayName = target.display_name || target.username || req.params.oid;

    const assessmentRow = stmtGetAssessment.get(req.params.oid, req.user.tenant);
    if (!assessmentRow) return res.status(404).json({ error: "No assessment data found for this user" });
    let allAssessments;
    try { allAssessments = JSON.parse(assessmentRow.data)?.assessments || {}; } catch { allAssessments = {}; }

    const toEndorse = Array.isArray(practiceIds) && practiceIds.length
      ? practiceIds
      : Object.keys(allAssessments);

    const endorsedIds = [];
    const stmtFindLatestVersion = db.prepare(
      "SELECT MAX(id) AS id FROM practice_versions WHERE practice_id = ? AND user_oid = ? AND tenant_id = ?"
    );

    const endorseTx = db.transaction(() => {
      for (const pid of toEndorse) {
        const assessData = allAssessments[pid];
        if (!assessData) continue;

        /* Find the latest existing version for this user/practice */
        const existing = stmtFindLatestVersion.get(pid, req.params.oid, req.user.tenant);

        let versionId;
        if (existing?.id) {
          versionId = existing.id;
        } else {
          /* No version yet — create one from current assessment data */
          const ins = stmtInsertPracticeVersion.run(
            pid, req.params.oid, displayName, req.user.tenant, JSON.stringify(assessData)
          );
          versionId = Number(ins.lastInsertRowid);
        }

        stmtUpsertEndorsement.run(pid, req.user.tenant, Number(versionId), endorsedBy);
        endorsedIds.push(pid);
      }
    });

    endorseTx();

    try {
      stmtInsertAudit.run(
        req.user.oid, req.user.username, req.dbUser.display_name,
        `USER:${target.username || req.params.oid}`, "endorse_contributions",
        "", `${endorsedIds.length} practices`
      );
    } catch { /* audit failure is non-fatal */ }

    res.json({ endorsed: endorsedIds.length, practiceIds: endorsedIds });
  } catch (err) {
    console.error("[AESCSF API] endorse-contributions error:", err);
    res.status(500).json({ error: err.message || "Endorsement failed" });
  }
});

/* ── Endorsement routes ──────────────────────────────────────────────────── */

/* All authenticated users: fetch current endorsements for pre-fill */
app.get("/api/endorsements", requireAuth, autoRegister, (req, res) => {
  const rows = stmtGetAllEndorsements.all(req.user.tenant);
  const result = {};
  for (const row of rows) {
    try {
      result[row.practice_id] = {
        version_id:    row.version_id,
        endorsed_by:   row.endorsed_by,
        endorsed_at:   row.endorsed_at,
        data:          JSON.parse(row.data),
        changed_since: row.changed_since > 0
      };
    } catch { /* skip corrupt row */ }
  }
  res.json(result);
});

/* Admin: get version history for a specific practice */
app.get("/api/admin/practices/:id/versions", requireAuth, autoRegister, (req, res) => {
  if (req.dbUser.role !== "admin") return res.status(403).json({ error: "Admin only" });
  const rows = stmtGetPracticeVersions.all(req.params.id, req.user.tenant);
  res.json(rows.map(r => { try { return { ...r, data: JSON.parse(r.data) }; } catch { return r; } }));
});

/* Admin: endorse a specific version of a practice */
app.post("/api/admin/practices/:id/endorse", requireAuth, autoRegister, (req, res) => {
  if (req.dbUser.role !== "admin") return res.status(403).json({ error: "Admin only" });
  const versionId = parseInt(req.body?.versionId);
  if (!versionId) return res.status(400).json({ error: "versionId required" });
  const version = stmtVerifyVersion.get(versionId, req.user.tenant, req.params.id);
  if (!version) return res.status(404).json({ error: "Version not found" });
  const endorsedBy = req.dbUser.display_name || req.user.username || "";
  stmtUpsertEndorsement.run(req.params.id, req.user.tenant, versionId, endorsedBy);
  res.json({ endorsed: true, practiceId: req.params.id, versionId });
});

/* Admin: remove endorsement for a practice */
app.delete("/api/admin/practices/:id/endorsement", requireAuth, autoRegister, (req, res) => {
  if (req.dbUser.role !== "admin") return res.status(403).json({ error: "Admin only" });
  stmtDeleteEndorsement.run(req.params.id, req.user.tenant);
  res.json({ removed: true });
});

/* ── Golden snapshot routes (tenant-wide; admin-write, all-read) ────────── */

app.get("/api/snapshots/golden", requireAuth, autoRegister, (req, res) => {
  res.json(stmtListGoldenSnapshots.all(req.user.tenant));
});

app.get("/api/snapshots/golden/:id", requireAuth, autoRegister, (req, res) => {
  const row = stmtGetGoldenSnapshot.get(req.params.id, req.user.tenant);
  if (!row) return res.status(404).json({ error: "Golden snapshot not found" });
  try {
    const parsed = JSON.parse(row.data);
    res.json({ id: row.id, label: row.label, created_at: row.created_at, golden: true, ...parsed });
  } catch {
    res.status(500).json({ error: "Corrupt snapshot data" });
  }
});

app.post("/api/snapshots/golden", requireAuth, autoRegister, (req, res) => {
  if (req.dbUser.role !== "admin") return res.status(403).json({ error: "Admin only" });
  const label = (req.body?.label || "").trim();
  if (!label) return res.status(400).json({ error: "label is required" });

  let payload = req.body?.data;
  if (!payload || typeof payload !== "object") {
    const row = stmtGetAssessment.get(req.user.oid, req.user.tenant);
    if (!row) return res.status(404).json({ error: "No assessment to snapshot — save your assessment first" });
    try { payload = JSON.parse(row.data); } catch { return res.status(500).json({ error: "Corrupt assessment data" }); }
  }

  try {
    const result = stmtInsertGoldenSnapshot.run(req.user.oid, req.user.tenant, label, JSON.stringify(payload));
    res.status(201).json({ id: result.lastInsertRowid, label, created_at: Math.floor(Date.now() / 1000), golden: true });
  } catch (err) {
    console.error("[AESCSF API] Golden snapshot insert error:", err);
    res.status(500).json({ error: "Failed to save golden snapshot" });
  }
});

app.delete("/api/snapshots/golden/:id", requireAuth, autoRegister, (req, res) => {
  if (req.dbUser.role !== "admin") return res.status(403).json({ error: "Admin only" });
  const info = stmtDeleteGoldenSnapshot.run(req.params.id, req.user.tenant);
  if (info.changes === 0) return res.status(404).json({ error: "Golden snapshot not found" });
  res.json({ deleted: true });
});

/* ── Snapshot routes ─────────────────────────────────────────────────────── */

app.get("/api/snapshots", requireAuth, autoRegister, (req, res) => {
  if (req.dbUser.role === "admin") {
    /* Admins see all personal snapshots from any admin in the same tenant */
    const rows = db.prepare(`
      SELECT s.id, s.label, s.created_at,
             COALESCE(u.display_name, u.username, s.user_oid) AS created_by
      FROM   snapshots s
      LEFT   JOIN users u ON u.oid = s.user_oid
      WHERE  s.tenant_id = ? AND s.scope = 'personal'
        AND  (u.role = 'admin' OR u.oid IS NULL)
      ORDER  BY s.created_at DESC
    `).all(req.user.tenant);
    return res.json(rows);
  }
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
  /* Admins can load any personal snapshot in their tenant; users only their own */
  const row = req.dbUser.role === "admin"
    ? db.prepare("SELECT id, label, data, created_at FROM snapshots WHERE id = ? AND tenant_id = ? AND scope = 'personal'").get(req.params.id, req.user.tenant)
    : stmtGetSnapshot.get(req.params.id, req.user.oid, req.user.tenant);
  if (!row) return res.status(404).json({ error: "Snapshot not found" });
  try {
    const parsed = JSON.parse(row.data);
    res.json({ id: row.id, label: row.label, created_at: row.created_at, ...parsed });
  } catch {
    res.status(500).json({ error: "Corrupt snapshot data" });
  }
});

app.delete("/api/snapshots/:id", requireAuth, autoRegister, (req, res) => {
  /* Admins can delete any personal snapshot in their tenant */
  const info = req.dbUser.role === "admin"
    ? db.prepare("DELETE FROM snapshots WHERE id = ? AND tenant_id = ? AND scope = 'personal'").run(req.params.id, req.user.tenant)
    : stmtDeleteSnapshot.run(req.params.id, req.user.oid, req.user.tenant);
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
app.get("/api/audit/export", exportLimiter, requireAuth, autoRegister, (req, res) => {
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

/**
 * DELETE /api/audit/purge
 * Admin-only: immediately purge audit entries older than AUDIT_RETENTION_DAYS.
 * Returns { deleted, retentionDays }.
 */
app.delete("/api/audit/purge", requireAuth, autoRegister, requireAdmin, (req, res) => {
  if (!stmtPurgeAudit) {
    return res.json({ deleted: 0, retentionDays: 0, message: "Retention is disabled (AESCSF_AUDIT_RETENTION_DAYS=0)" });
  }
  try {
    const result = purgeAuditLog();
    res.json(result);
  } catch (err) {
    console.error("[AESCSF API] Audit purge error:", err);
    res.status(500).json({ error: "Purge failed" });
  }
});

/* ── Objective assignment routes ────────────────────────────────────────────────── */

/**
 * PUT /api/admin/users/:oid/objective-assignments
 * Body: { objectives: ["ACCESS-1", "ARCHITECTURE-2", ...] }
 * Admin only. Replaces the user's objective assignments atomically.
 */
app.put("/api/admin/users/:oid/objective-assignments", requireAuth, autoRegister, requireAdmin, (req, res) => {
  const { objectives } = req.body || {};
  if (!Array.isArray(objectives)) return res.status(400).json({ error: "objectives must be an array" });
  const target = stmtGetUser.get(req.params.oid);
  if (!target) return res.status(404).json({ error: "User not found" });

  const oldObjectives = getUserObjectiveAssignments(req.params.oid).sort().join(",");
  const setObjectives = db.transaction((oid, list, byOid) => {
    stmtDeleteObjectiveAssignments.run(oid);
    for (const obj of list) stmtInsertObjectiveAssignment.run(oid, obj, byOid);
  });
  setObjectives(req.params.oid, objectives, req.user.oid);

  const newObjectives = objectives.slice().sort().join(",");
  if (oldObjectives !== newObjectives) {
    stmtInsertAudit.run(
      req.user.oid, req.user.username, req.dbUser.display_name,
      `USER:${target.username || target.oid}`, "objective_assignments",
      oldObjectives, newObjectives
    );
  }
  res.json({ updated: true, oid: req.params.oid, objectives });
});

/**
 * GET /api/admin/responses
 * Returns per-practice responses from all non-admin users who have saved data.
 * Shape: { [practiceId]: [{ user_oid, display_name, username, assessment }] }
 * Admin only.
 */
app.get("/api/admin/responses", requireAuth, autoRegister, requireAdmin, (req, res) => {
  try {
    const allUsers = db.prepare(
      "SELECT oid, username, display_name, role FROM users WHERE tenant_id = ?"
    ).all(req.user.tenant);
    const usersByOid = Object.fromEntries(allUsers.map(u => [u.oid, u]));
    const nonAdminOids = new Set(allUsers.filter(u => u.role !== "admin").map(u => u.oid));

    const allRows = db.prepare(
      "SELECT user_oid, data FROM assessments WHERE tenant_id = ?"
    ).all(req.user.tenant);

    const responses = {};
    for (const row of allRows) {
      if (!nonAdminOids.has(row.user_oid)) continue;
      const user = usersByOid[row.user_oid];
      try {
        const assessments = JSON.parse(row.data)?.assessments || {};
        for (const [practiceId, assessment] of Object.entries(assessments)) {
          if (!responses[practiceId]) responses[practiceId] = [];
          responses[practiceId].push({
            user_oid:     row.user_oid,
            display_name: user?.display_name || row.user_oid,
            username:     user?.username     || row.user_oid,
            assessment
          });
        }
      } catch { /* skip corrupt row */ }
    }
    res.json(responses);
  } catch (err) {
    console.error("[AESCSF API] Responses error:", err);
    res.status(500).json({ error: "Failed to load responses" });
  }
});

/* ── Confidence rating routes ──────────────────────────────────────────────── */

/**
 * GET /api/admin/confidence
 * Returns all confidence ratings for this tenant as { [practiceId]: { rating, notes, updatedAt } }.
 * Admin only.
 */
app.get("/api/admin/confidence", requireAuth, autoRegister, requireAdmin, (req, res) => {
  try {
    const rows = stmtGetAllConfidence.all(req.user.tenant);
    const result = {};
    for (const row of rows) {
      result[row.practice_id] = { rating: row.rating, notes: row.notes, updatedAt: row.updated_at };
    }
    res.json(result);
  } catch (err) {
    console.error("[AESCSF API] Confidence get error:", err);
    res.status(500).json({ error: "Failed to load confidence ratings" });
  }
});

/**
 * PUT /api/admin/confidence/:practiceId
 * Body: { rating: 0–5, notes?: string }
 * Admin only. Writes to audit_log using the practice_id as the record key.
 */
app.put("/api/admin/confidence/:practiceId", requireAuth, autoRegister, requireAdmin, (req, res) => {
  const { rating, notes = "" } = req.body;
  if (typeof rating !== "number" || !Number.isInteger(rating) || rating < 0 || rating > 5) {
    return res.status(400).json({ error: "rating must be an integer 0–5" });
  }
  if (typeof notes !== "string") {
    return res.status(400).json({ error: "notes must be a string" });
  }
  const practiceId = req.params.practiceId;
  try {
    const existing = db.prepare(
      "SELECT rating, notes FROM confidence_ratings WHERE practice_id = ? AND tenant_id = ?"
    ).get(practiceId, req.user.tenant);

    stmtUpsertConfidence.run(practiceId, req.user.tenant, rating, notes.slice(0, 2000), req.user.oid);

    const oldRating = existing?.rating ?? null;
    const oldNotes  = existing?.notes  ?? "";
    if (oldRating !== rating) {
      stmtInsertAudit.run(
        req.user.oid, req.user.username, req.dbUser.display_name,
        practiceId, "confidence_rating",
        oldRating === null ? "" : String(oldRating),
        String(rating)
      );
    }
    if (notes !== oldNotes) {
      stmtInsertAudit.run(
        req.user.oid, req.user.username, req.dbUser.display_name,
        practiceId, "confidence_notes",
        oldNotes.slice(0, MAX_AUDIT_VALUE_LEN),
        notes.slice(0, MAX_AUDIT_VALUE_LEN)
      );
    }
    res.json({ ok: true });
  } catch (err) {
    console.error("[AESCSF API] Confidence set error:", err);
    res.status(500).json({ error: "Failed to save confidence rating" });
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
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`[AESCSF API] Listening on port ${PORT}`);
  console.log(`[AESCSF API] SSO: ${SSO_ENABLED ? "EntraID (oauth2-proxy)" : "DISABLED"}`);
  console.log(`[AESCSF API] Admin OIDs: ${ADMIN_OIDS.length ? `${ADMIN_OIDS.length} configured` : "(first user will become admin)"}`);
  console.log(`[AESCSF API] DB:      ${path.join(DATA_DIR, "aescsf.db")}`);
  console.log(`[AESCSF API] Uploads: ${UPLOAD_DIR}`);
});

/* ── Graceful shutdown ───────────────────────────────────────────────────── */
function shutdown(signal) {
  console.log(`[AESCSF API] ${signal} received — shutting down gracefully`);
  server.close(() => {
    db.close();
    console.log("[AESCSF API] DB closed. Exiting.");
    process.exit(0);
  });
  // Force exit if connections don't drain within 10 s
  setTimeout(() => {
    console.warn("[AESCSF API] Forced exit after 10 s shutdown timeout");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));
