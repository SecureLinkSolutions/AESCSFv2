/**
 * Multi-tenant isolation regression test.
 *
 * Run with:  npm test          (from the server/ directory)
 *
 * Starts the real API on a scratch database and forges oauth2-proxy style
 * identity headers for two admins in DIFFERENT Entra tenants, then asserts
 * that neither can read, enumerate, or destroy the other's data.
 *
 * The API deliberately decodes the access token without verifying its
 * signature — oauth2-proxy is trusted to have done that, and nginx strips
 * client-supplied X-Auth-Request-* headers — so an unsigned token is
 * sufficient to drive this test.
 *
 * These checks exist because every one of them was a real defect:
 * admin endpoints were querying users, assessments, audit entries and
 * evidence files without ever filtering on tenant_id.
 */
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import Database from "better-sqlite3";

const SERVER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "aescsf-tenant-test-"));
const PORT = Number(process.env.TEST_PORT || 3998);
const BASE = `http://127.0.0.1:${PORT}`;
const DB_PATH = path.join(DATA_DIR, "aescsf.db");

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const tok = (oid, tid, name) => `x.${b64({ oid, tid, name, preferred_username: name })}.y`;

const A = { oid: "oid-alice", tid: "tenant-AAA", email: "alice@aaa.example" };
const B = { oid: "oid-bob", tid: "tenant-BBB", email: "bob@bbb.example" };
const hdr = (u) => ({
  "X-Auth-Request-User": u.email,
  "X-Auth-Request-Access-Token": tok(u.oid, u.tid, u.email),
  "Content-Type": "application/json",
});

const srv = spawn("node", ["server.js"], {
  cwd: SERVER_DIR,
  env: {
    ...process.env,
    DATA_DIR,
    PORT: String(PORT),
    AESCSF_SSO_ENABLED: "true",
    AESCSF_ADMIN_OIDS: `${A.oid},${B.oid}`, // each is an admin of their own tenant
    AESCSF_AUDIT_RETENTION_DAYS: "30",
    AESCSF_AUTO_SNAPSHOT: "off",
  },
  stdio: ["ignore", "pipe", "pipe"],
});
let serverLog = "";
srv.stdout.on("data", (d) => (serverLog += d));
srv.stderr.on("data", (d) => (serverLog += d));

const results = [];
const check = (name, pass, detail = "") => {
  results.push({ name, pass });
  console.log(`${pass ? "ok  " : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};

const saveAssessment = (u, practiceId, notes) =>
  fetch(`${BASE}/api/assessment`, {
    method: "PUT",
    headers: hdr(u),
    body: JSON.stringify({
      assessments: {
        [practiceId]: {
          status: "Yes", notes, evidence: "", owner: "",
          targetDate: "", lastReviewed: "", gap: "", attachments: "",
        },
      },
    }),
  });

try {
  for (let i = 0; i < 40; i++) {
    try { if ((await fetch(`${BASE}/api/health`)).ok) break; } catch { /* booting */ }
    await sleep(250);
  }

  check("alice can save her own assessment", (await saveAssessment(A, "ACCESS-1a", "alice-secret-note")).ok);
  check("bob can save his own assessment", (await saveAssessment(B, "ACCESS-1a", "bob-secret-note")).ok);

  /* Audit log reads */
  const auditA = await (await fetch(`${BASE}/api/audit`, { headers: hdr(A) })).text();
  const auditB = await (await fetch(`${BASE}/api/audit`, { headers: hdr(B) })).text();
  check("audit: alice sees her own entries (positive control)", auditA.includes("alice-secret-note"));
  check("audit: alice cannot see bob's entries", !auditA.includes("bob-secret-note"));
  check("audit: bob cannot see alice's entries", !auditB.includes("alice-secret-note"));

  const csvA = await (await fetch(`${BASE}/api/audit/export`, { headers: hdr(A) })).text();
  check("audit CSV export is tenant-scoped", !csvA.includes("bob-secret-note"));

  const histA = await (await fetch(`${BASE}/api/audit/practice/ACCESS-1a`, { headers: hdr(A) })).text();
  check("per-practice audit history is tenant-scoped", !histA.includes("bob-secret-note"));

  /* Assessment + user reads */
  const mergedA = await (await fetch(`${BASE}/api/admin/assessment/merged`, { headers: hdr(A) })).text();
  check("merged assessment is tenant-scoped", !mergedA.includes("bob-secret-note"));

  const usersA = await (await fetch(`${BASE}/api/admin/users`, { headers: hdr(A) })).text();
  check("user list cannot enumerate other tenants", !usersA.includes(B.email));

  /* Cross-tenant mutation */
  const roleRes = await fetch(`${BASE}/api/admin/users/${B.oid}/role`, {
    method: "PUT", headers: hdr(A), body: JSON.stringify({ role: "user" }),
  });
  check("cannot change another tenant's user role", roleRes.status === 404, `HTTP ${roleRes.status}`);

  /* Evidence files — inserted directly, since upload is multipart */
  {
    const db = new Database(DB_PATH);
    db.prepare(
      "INSERT INTO files (user_oid, tenant_id, practice_id, filename, stored_name, mime_type, size_bytes) VALUES (?,?,?,?,?,?,?)"
    ).run(B.oid, B.tid, "ACCESS-1a", "bob-confidential.pdf", "stored-b.pdf", "application/pdf", 10);
    db.close();
    const filesA = await (await fetch(`${BASE}/api/files/ACCESS-1a`, { headers: hdr(A) })).text();
    check("evidence file listing is tenant-scoped", !filesA.includes("bob-confidential"));
  }

  /* Audit purge must never cross tenants — it deletes, so a leak here is
     destruction of another organisation's compliance trail. */
  {
    const db = new Database(DB_PATH);
    db.prepare("UPDATE audit_log SET created_at = unixepoch() - (400*86400)").run();
    const bobBefore = db.prepare("SELECT COUNT(*) n FROM audit_log WHERE tenant_id = ?").get(B.tid).n;
    db.close();

    const purgeBody = await (await fetch(`${BASE}/api/audit/purge`, { method: "DELETE", headers: hdr(A) })).json();

    const db2 = new Database(DB_PATH);
    const bobAfter = db2.prepare("SELECT COUNT(*) n FROM audit_log WHERE tenant_id = ?").get(B.tid).n;
    const aliceAfter = db2.prepare("SELECT COUNT(*) n FROM audit_log WHERE tenant_id = ?").get(A.tid).n;
    db2.close();

    check("purge removes the caller's own expired entries", aliceAfter === 0, `alice rows left: ${aliceAfter}`);
    check("purge does not touch another tenant's audit trail",
      bobBefore > 0 && bobAfter === bobBefore, `bob before=${bobBefore} after=${bobAfter}`);
    check("purge count excludes other tenants", purgeBody.deleted === 2, `deleted=${purgeBody.deleted}`);
  }
} catch (err) {
  check("test harness", false, err.stack);
} finally {
  srv.kill("SIGTERM");
  await sleep(400);
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
}

const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) {
  console.log("\nLast server output:\n" + serverLog.split("\n").slice(-25).join("\n"));
  process.exit(1);
}
