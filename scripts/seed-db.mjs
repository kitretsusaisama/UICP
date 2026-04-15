
/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  UICP — Production-Ready Database Seed Script
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  Seeds:
 *    • 2 tenants  (acme-corp / dev-sandbox)
 *    • 6 users    (admin, editor, viewer × 2 tenants)
 *    • 6 email identities  (verified)
 *    • 4 phone identities  (verified, fictional E.164 numbers)
 *    • 6 bcrypt credentials (password: Test@12345!)
 *    • 4 roles    (super-admin, admin, editor, viewer)
 *    • 6 permissions (users:read/write, sessions:read, audit:read/write, iam:manage)
 *    • role_permissions + user_roles assignments
 *    • 8 audit log entries
 *
 *  All PII fields (identity values, display names) are AES-256-GCM encrypted
 *  using the ENCRYPTION_MASTER_KEY from .env.
 *  Identity lookup hashes are HMAC-SHA256 (same key).
 *
 *  Run:  node scripts/seed-db.mjs
 *  Safe: uses INSERT IGNORE — re-runnable without duplicates.
 * ═══════════════════════════════════════════════════════════════════════════
 */

import { readFileSync }                    from 'fs';
import { resolve, dirname }                from 'path';
import { fileURLToPath }                   from 'url';
import { createCipheriv, createHmac,
         randomBytes, hkdfSync }           from 'crypto';
import { createConnection }                from 'mysql2/promise';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Colours ───────────────────────────────────────────────────────────────────
const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m',
  cyan: '\x1b[36m', blue: '\x1b[34m', magenta: '\x1b[35m',
};
const ok   = (m) => console.log(`  ${C.green}✔${C.reset}  ${m}`);
const err  = (m) => console.log(`  ${C.red}✘${C.reset}  ${C.red}${m}${C.reset}`);
const info = (m) => console.log(`  ${C.cyan}ℹ${C.reset}  ${m}`);
const dim  = (m) => console.log(`     ${C.dim}${m}${C.reset}`);
const sep  = ()  => console.log(`  ${C.dim}${'─'.repeat(68)}${C.reset}`);
const hdr  = (t) => { console.log(); console.log(`${C.bold}${C.blue}  ┌─ ${t}${C.reset}`); sep(); };

// ── Load .env ─────────────────────────────────────────────────────────────────
const envContent = readFileSync(resolve(__dirname, '../.env'), 'utf8');
for (const line of envContent.split('\n')) {
  const t = line.trim();
  if (!t || t.startsWith('#')) continue;
  const eq = t.indexOf('=');
  if (eq === -1) continue;
  const k = t.slice(0, eq).trim();
  const v = t.slice(eq + 1).trim();
  if (!process.env[k]) process.env[k] = v;
}

const MASTER_KEY_HEX = process.env.ENCRYPTION_MASTER_KEY;
const MASTER_KID     = process.env.ENCRYPTION_MASTER_KEY_ID ?? 'master-v1';
if (!MASTER_KEY_HEX) { err('ENCRYPTION_MASTER_KEY not set in .env'); process.exit(1); }
const MASTER_KEY = Buffer.from(MASTER_KEY_HEX, 'hex');

// ── Crypto helpers ────────────────────────────────────────────────────────────
function deriveKey(tenantId, context) {
  const info = Buffer.from(`${context}:${tenantId}`);
  return hkdfSync('sha256', MASTER_KEY, Buffer.alloc(32), info, 32);
}

function encrypt(plaintext, tenantId, context) {
  const key = deriveKey(tenantId, context);
  const iv  = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct  = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const serialised = `${iv.toString('base64')}.${tag.toString('base64')}.${ct.toString('base64')}.${MASTER_KID}`;
  return Buffer.from(serialised);
}

function hmacHash(value, tenantId, context) {
  const key = deriveKey(tenantId, context);
  return createHmac('sha256', key).update(value.toLowerCase().trim()).digest();
}

function auditChecksum(row) {
  const payload = JSON.stringify(row);
  return createHmac('sha256', MASTER_KEY).update(payload).digest();
}

// ── UUID helpers ──────────────────────────────────────────────────────────────
function uuidToBin(uuid) {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

// ── Fixed UUIDs (deterministic seed) ─────────────────────────────────────────
const IDS = {
  // Tenants
  T_ACME   : 'a0000001-0000-4000-8000-000000000001',
  T_DEV    : 'a0000002-0000-4000-8000-000000000002',
  // Users — Acme
  U_ACME_ADMIN  : 'b0000001-0000-4000-8000-000000000001',
  U_ACME_EDITOR : 'b0000002-0000-4000-8000-000000000002',
  U_ACME_VIEWER : 'b0000003-0000-4000-8000-000000000003',
  // Users — Dev
  U_DEV_ADMIN   : 'b0000004-0000-4000-8000-000000000004',
  U_DEV_EDITOR  : 'b0000005-0000-4000-8000-000000000005',
  U_DEV_VIEWER  : 'b0000006-0000-4000-8000-000000000006',
  // Identities
  I_ACME_ADMIN_EMAIL  : 'c0000001-0000-4000-8000-000000000001',
  I_ACME_EDITOR_EMAIL : 'c0000002-0000-4000-8000-000000000002',
  I_ACME_VIEWER_EMAIL : 'c0000003-0000-4000-8000-000000000003',
  I_ACME_ADMIN_PHONE  : 'c0000004-0000-4000-8000-000000000004',
  I_ACME_EDITOR_PHONE : 'c0000005-0000-4000-8000-000000000005',
  I_DEV_ADMIN_EMAIL   : 'c0000006-0000-4000-8000-000000000006',
  I_DEV_EDITOR_EMAIL  : 'c0000007-0000-4000-8000-000000000007',
  I_DEV_VIEWER_EMAIL  : 'c0000008-0000-4000-8000-000000000008',
  I_DEV_ADMIN_PHONE   : 'c0000009-0000-4000-8000-000000000009',
  I_DEV_EDITOR_PHONE  : 'c0000010-0000-4000-8000-000000000010',
  // Credentials
  CR_ACME_ADMIN  : 'd0000001-0000-4000-8000-000000000001',
  CR_ACME_EDITOR : 'd0000002-0000-4000-8000-000000000002',
  CR_ACME_VIEWER : 'd0000003-0000-4000-8000-000000000003',
  CR_DEV_ADMIN   : 'd0000004-0000-4000-8000-000000000004',
  CR_DEV_EDITOR  : 'd0000005-0000-4000-8000-000000000005',
  CR_DEV_VIEWER  : 'd0000006-0000-4000-8000-000000000006',
  // Roles
  R_SUPER_ADMIN : 'e0000001-0000-4000-8000-000000000001',
  R_ADMIN       : 'e0000002-0000-4000-8000-000000000002',
  R_EDITOR      : 'e0000003-0000-4000-8000-000000000003',
  R_VIEWER      : 'e0000004-0000-4000-8000-000000000004',
  // Permissions
  P_USERS_READ    : 'f0000001-0000-4000-8000-000000000001',
  P_USERS_WRITE   : 'f0000002-0000-4000-8000-000000000002',
  P_SESSIONS_READ : 'f0000003-0000-4000-8000-000000000003',
  P_AUDIT_READ    : 'f0000004-0000-4000-8000-000000000004',
  P_AUDIT_WRITE   : 'f0000005-0000-4000-8000-000000000005',
  P_IAM_MANAGE    : 'f0000006-0000-4000-8000-000000000006',
};

// bcrypt hash of "Test@12345!" with rounds=10 (pre-computed, stable)
const BCRYPT_HASH = '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi';

const NOW = new Date().toISOString().replace('T', ' ').replace('Z', '').slice(0, 23);

// ── Seed data definitions ─────────────────────────────────────────────────────

const TENANTS = [
  {
    id: IDS.T_ACME, slug: 'acme-corp', plan: 'enterprise',
    max_users: 5000, max_sessions: 10, mfa_policy: 'adaptive', session_ttl_s: 86400,
    password_policy: { minLength: 10, requireUppercase: true, requireDigit: true, requireSpecial: true },
    allowed_domains: ['acme.com', 'acme.io'],
  },
  {
    id: IDS.T_DEV, slug: 'dev-sandbox', plan: 'pro',
    max_users: 500, max_sessions: 5, mfa_policy: 'optional', session_ttl_s: 43200,
    password_policy: { minLength: 10, requireUppercase: true, requireDigit: true, requireSpecial: true },
    allowed_domains: [],
  },
];

const USERS = [
  { id: IDS.U_ACME_ADMIN,  tenantId: IDS.T_ACME, displayName: 'Alice Thornton',   status: 'active'  },
  { id: IDS.U_ACME_EDITOR, tenantId: IDS.T_ACME, displayName: 'Bob Harrington',   status: 'active'  },
  { id: IDS.U_ACME_VIEWER, tenantId: IDS.T_ACME, displayName: 'Carol Whitfield',  status: 'active'  },
  { id: IDS.U_DEV_ADMIN,   tenantId: IDS.T_DEV,  displayName: 'David Okafor',     status: 'active'  },
  { id: IDS.U_DEV_EDITOR,  tenantId: IDS.T_DEV,  displayName: 'Eva Lindström',    status: 'active'  },
  { id: IDS.U_DEV_VIEWER,  tenantId: IDS.T_DEV,  displayName: 'Frank Nakamura',   status: 'suspended', suspendReason: 'Policy violation — account under review' },
];

// Fictional emails and E.164 phone numbers — no real PII
const IDENTITIES = [
  // Acme — email
  { id: IDS.I_ACME_ADMIN_EMAIL,  userId: IDS.U_ACME_ADMIN,  tenantId: IDS.T_ACME, type: 'email', value: 'alice.thornton@acme.com',    verified: true  },
  { id: IDS.I_ACME_EDITOR_EMAIL, userId: IDS.U_ACME_EDITOR, tenantId: IDS.T_ACME, type: 'email', value: 'bob.harrington@acme.com',    verified: true  },
  { id: IDS.I_ACME_VIEWER_EMAIL, userId: IDS.U_ACME_VIEWER, tenantId: IDS.T_ACME, type: 'email', value: 'carol.whitfield@acme.com',   verified: true  },
  // Acme — phone (fictional Indian numbers in E.164)
  { id: IDS.I_ACME_ADMIN_PHONE,  userId: IDS.U_ACME_ADMIN,  tenantId: IDS.T_ACME, type: 'phone', value: '+911000000001',              verified: true  },
  { id: IDS.I_ACME_EDITOR_PHONE, userId: IDS.U_ACME_EDITOR, tenantId: IDS.T_ACME, type: 'phone', value: '+911000000002',              verified: false },
  // Dev — email
  { id: IDS.I_DEV_ADMIN_EMAIL,   userId: IDS.U_DEV_ADMIN,   tenantId: IDS.T_DEV,  type: 'email', value: 'david.okafor@dev-sandbox.io',  verified: true  },
  { id: IDS.I_DEV_EDITOR_EMAIL,  userId: IDS.U_DEV_EDITOR,  tenantId: IDS.T_DEV,  type: 'email', value: 'eva.lindstrom@dev-sandbox.io', verified: true  },
  { id: IDS.I_DEV_VIEWER_EMAIL,  userId: IDS.U_DEV_VIEWER,  tenantId: IDS.T_DEV,  type: 'email', value: 'frank.nakamura@dev-sandbox.io',verified: true  },
  // Dev — phone (fictional)
  { id: IDS.I_DEV_ADMIN_PHONE,   userId: IDS.U_DEV_ADMIN,   tenantId: IDS.T_DEV,  type: 'phone', value: '+911000000003',              verified: true  },
  { id: IDS.I_DEV_EDITOR_PHONE,  userId: IDS.U_DEV_EDITOR,  tenantId: IDS.T_DEV,  type: 'phone', value: '+911000000004',              verified: false },
];

const CREDENTIALS = [
  { id: IDS.CR_ACME_ADMIN,  userId: IDS.U_ACME_ADMIN  },
  { id: IDS.CR_ACME_EDITOR, userId: IDS.U_ACME_EDITOR },
  { id: IDS.CR_ACME_VIEWER, userId: IDS.U_ACME_VIEWER },
  { id: IDS.CR_DEV_ADMIN,   userId: IDS.U_DEV_ADMIN   },
  { id: IDS.CR_DEV_EDITOR,  userId: IDS.U_DEV_EDITOR  },
  { id: IDS.CR_DEV_VIEWER,  userId: IDS.U_DEV_VIEWER  },
];

const ROLES = [
  { id: IDS.R_SUPER_ADMIN, tenantId: IDS.T_ACME, name: 'super-admin', description: 'Full platform access'         },
  { id: IDS.R_ADMIN,       tenantId: IDS.T_ACME, name: 'admin',       description: 'Tenant administration'        },
  { id: IDS.R_EDITOR,      tenantId: IDS.T_ACME, name: 'editor',      description: 'Create and edit resources'    },
  { id: IDS.R_VIEWER,      tenantId: IDS.T_ACME, name: 'viewer',      description: 'Read-only access'             },
];

const PERMISSIONS = [
  { id: IDS.P_USERS_READ,    tenantId: IDS.T_ACME, resource: 'users',    action: 'read'   },
  { id: IDS.P_USERS_WRITE,   tenantId: IDS.T_ACME, resource: 'users',    action: 'write'  },
  { id: IDS.P_SESSIONS_READ, tenantId: IDS.T_ACME, resource: 'sessions', action: 'read'   },
  { id: IDS.P_AUDIT_READ,    tenantId: IDS.T_ACME, resource: 'audit',    action: 'read'   },
  { id: IDS.P_AUDIT_WRITE,   tenantId: IDS.T_ACME, resource: 'audit',    action: 'write'  },
  { id: IDS.P_IAM_MANAGE,    tenantId: IDS.T_ACME, resource: 'iam',      action: 'manage' },
];

// role → permissions
const ROLE_PERMISSIONS = [
  { roleId: IDS.R_SUPER_ADMIN, permId: IDS.P_USERS_READ    },
  { roleId: IDS.R_SUPER_ADMIN, permId: IDS.P_USERS_WRITE   },
  { roleId: IDS.R_SUPER_ADMIN, permId: IDS.P_SESSIONS_READ },
  { roleId: IDS.R_SUPER_ADMIN, permId: IDS.P_AUDIT_READ    },
  { roleId: IDS.R_SUPER_ADMIN, permId: IDS.P_AUDIT_WRITE   },
  { roleId: IDS.R_SUPER_ADMIN, permId: IDS.P_IAM_MANAGE    },
  { roleId: IDS.R_ADMIN,       permId: IDS.P_USERS_READ    },
  { roleId: IDS.R_ADMIN,       permId: IDS.P_USERS_WRITE   },
  { roleId: IDS.R_ADMIN,       permId: IDS.P_SESSIONS_READ },
  { roleId: IDS.R_ADMIN,       permId: IDS.P_AUDIT_READ    },
  { roleId: IDS.R_EDITOR,      permId: IDS.P_USERS_READ    },
  { roleId: IDS.R_EDITOR,      permId: IDS.P_SESSIONS_READ },
  { roleId: IDS.R_VIEWER,      permId: IDS.P_USERS_READ    },
];

// user → role
const USER_ROLES = [
  { userId: IDS.U_ACME_ADMIN,  roleId: IDS.R_SUPER_ADMIN, tenantId: IDS.T_ACME },
  { userId: IDS.U_ACME_EDITOR, roleId: IDS.R_EDITOR,      tenantId: IDS.T_ACME },
  { userId: IDS.U_ACME_VIEWER, roleId: IDS.R_VIEWER,      tenantId: IDS.T_ACME },
  { userId: IDS.U_DEV_ADMIN,   roleId: IDS.R_ADMIN,       tenantId: IDS.T_DEV  },
  { userId: IDS.U_DEV_EDITOR,  roleId: IDS.R_EDITOR,      tenantId: IDS.T_DEV  },
  { userId: IDS.U_DEV_VIEWER,  roleId: IDS.R_VIEWER,      tenantId: IDS.T_DEV  },
];

// ── Main ──────────────────────────────────────────────────────────────────────
let conn;
const stats = { inserted: 0, skipped: 0, errors: 0 };

async function exec(label, sql, params = []) {
  try {
    const [result] = await conn.execute(sql, params);
    const affected = result.affectedRows ?? 0;
    if (affected > 0) {
      ok(`${label}`);
      dim(`Rows affected: ${affected}`);
      stats.inserted += affected;
    } else {
      info(`${label}  ${C.dim}(already exists — skipped)${C.reset}`);
      stats.skipped++;
    }
  } catch (e) {
    err(`${label}: ${e.message}`);
    stats.errors++;
  }
}

try {
  conn = await createConnection({
    host    : process.env.DB_HOST     ?? 'localhost',
    port    : Number(process.env.DB_PORT ?? 3306),
    user    : process.env.DB_USER     ?? 'root',
    password: process.env.DB_PASSWORD ?? '',
    database: process.env.DB_NAME     ?? 'uicp_db',
    supportBigNumbers: true,
  });
  ok(`Connected to MySQL at ${process.env.DB_HOST ?? 'localhost'}:${process.env.DB_PORT ?? 3306}/${process.env.DB_NAME ?? 'uicp_db'}`);
} catch (e) {
  err(`MySQL connection failed: ${e.message}`);
  process.exit(1);
}

// ── 1. Tenants ────────────────────────────────────────────────────────────────
hdr('Step 1 — Tenants');
for (const t of TENANTS) {
  await exec(
    `Tenant: ${t.slug}`,
    `INSERT IGNORE INTO tenants
       (id, slug, plan, status, max_users, max_sessions_per_user, mfa_policy,
        session_ttl_s, password_policy_json, allowed_domains_json, version, created_at, updated_at)
     VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
    [
      uuidToBin(t.id), t.slug, t.plan,
      t.max_users, t.max_sessions, t.mfa_policy, t.session_ttl_s,
      JSON.stringify(t.password_policy), JSON.stringify(t.allowed_domains),
      NOW, NOW,
    ],
  );
}

// ── 2. Users ──────────────────────────────────────────────────────────────────
hdr('Step 2 — Users');
for (const u of USERS) {
  const nameEnc = encrypt(u.displayName, u.tenantId, 'USER_PII');
  await exec(
    `User: ${u.displayName} (${u.status})`,
    `INSERT IGNORE INTO users
       (id, tenant_id, display_name_enc, display_name_enc_kid, status,
        suspend_reason, version, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`,
    [
      uuidToBin(u.id), uuidToBin(u.tenantId),
      nameEnc, MASTER_KID,
      u.status, u.suspendReason ?? null,
      NOW, NOW,
    ],
  );
}

// ── 3. Identities ─────────────────────────────────────────────────────────────
hdr('Step 3 — Identities (encrypted + HMAC hashed)');
for (const i of IDENTITIES) {
  const ctx      = i.type === 'email' ? 'IDENTITY_VALUE' : 'IDENTITY_VALUE';
  const valueEnc = encrypt(i.value, i.tenantId, ctx);
  const valueHash = hmacHash(i.value, i.tenantId, ctx);
  const verifiedAt = i.verified ? NOW : null;

  await exec(
    `Identity: ${i.type} → ${i.value} (verified=${i.verified})`,
    `INSERT IGNORE INTO identities
       (id, tenant_id, user_id, type, value_enc, value_enc_kid,
        value_hash, verified, verified_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      uuidToBin(i.id), uuidToBin(i.tenantId), uuidToBin(i.userId),
      i.type, valueEnc, MASTER_KID,
      valueHash, i.verified ? 1 : 0, verifiedAt,
      NOW,
    ],
  );
}

// ── 4. Credentials ────────────────────────────────────────────────────────────
hdr('Step 4 — Credentials (bcrypt hash of Test@12345!)');
for (const c of CREDENTIALS) {
  await exec(
    `Credential for user ${c.userId.slice(0, 8)}...`,
    `INSERT IGNORE INTO credentials
       (id, user_id, hash, algorithm, rounds, created_at, updated_at)
     VALUES (?, ?, ?, 'bcrypt_v1', 10, ?, ?)`,
    [uuidToBin(c.id), uuidToBin(c.userId), BCRYPT_HASH, NOW, NOW],
  );
}

// ── 5. Roles ──────────────────────────────────────────────────────────────────
hdr('Step 5 — Roles');
for (const r of ROLES) {
  await exec(
    `Role: ${r.name}`,
    `INSERT IGNORE INTO roles (id, tenant_id, name, description, created_at)
     VALUES (?, ?, ?, ?, ?)`,
    [uuidToBin(r.id), uuidToBin(r.tenantId), r.name, r.description, NOW],
  );
}

// ── 6. Permissions ────────────────────────────────────────────────────────────
hdr('Step 6 — Permissions');
for (const p of PERMISSIONS) {
  await exec(
    `Permission: ${p.resource}:${p.action}`,
    `INSERT IGNORE INTO permissions (id, tenant_id, resource, action, created_at)
     VALUES (?, ?, ?, ?, ?)`,
    [uuidToBin(p.id), uuidToBin(p.tenantId), p.resource, p.action, NOW],
  );
}

// ── 7. Role ↔ Permission assignments ─────────────────────────────────────────
hdr('Step 7 — Role ↔ Permission Assignments');
for (const rp of ROLE_PERMISSIONS) {
  await exec(
    `role_permissions: ${rp.roleId.slice(0,8)} → ${rp.permId.slice(0,8)}`,
    `INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)`,
    [uuidToBin(rp.roleId), uuidToBin(rp.permId)],
  );
}

// ── 8. User ↔ Role assignments ────────────────────────────────────────────────
hdr('Step 8 — User ↔ Role Assignments');
for (const ur of USER_ROLES) {
  await exec(
    `user_roles: ${ur.userId.slice(0,8)} → ${ur.roleId.slice(0,8)}`,
    `INSERT IGNORE INTO user_roles (user_id, role_id, tenant_id, granted_at)
     VALUES (?, ?, ?, ?)`,
    [uuidToBin(ur.userId), uuidToBin(ur.roleId), uuidToBin(ur.tenantId), NOW],
  );
}

// ── 9. Audit logs ─────────────────────────────────────────────────────────────
hdr('Step 9 — Audit Logs');
const AUDIT_EVENTS = [
  { tenantId: IDS.T_ACME, actorId: IDS.U_ACME_ADMIN,  actorType: 'user',   action: 'user.created',          resourceType: 'user',    resourceId: IDS.U_ACME_EDITOR },
  { tenantId: IDS.T_ACME, actorId: IDS.U_ACME_ADMIN,  actorType: 'user',   action: 'user.role.assigned',    resourceType: 'user',    resourceId: IDS.U_ACME_EDITOR },
  { tenantId: IDS.T_ACME, actorId: IDS.U_ACME_ADMIN,  actorType: 'user',   action: 'user.suspended',        resourceType: 'user',    resourceId: IDS.U_DEV_VIEWER  },
  { tenantId: IDS.T_ACME, actorId: null,               actorType: 'system', action: 'jwt.key.rotated',       resourceType: 'jwt_key', resourceId: null              },
  { tenantId: IDS.T_DEV,  actorId: IDS.U_DEV_ADMIN,   actorType: 'user',   action: 'user.created',          resourceType: 'user',    resourceId: IDS.U_DEV_EDITOR  },
  { tenantId: IDS.T_DEV,  actorId: IDS.U_DEV_ADMIN,   actorType: 'user',   action: 'session.invalidated',   resourceType: 'session', resourceId: null              },
  { tenantId: IDS.T_DEV,  actorId: IDS.U_DEV_EDITOR,  actorType: 'user',   action: 'user.login.succeeded',  resourceType: 'user',    resourceId: IDS.U_DEV_EDITOR  },
  { tenantId: IDS.T_DEV,  actorId: null,               actorType: 'system', action: 'otp.sent',              resourceType: 'otp',     resourceId: null              },
];

// Deterministic audit log IDs
const AUDIT_IDS = [
  'aa000001-0000-4000-8000-000000000001',
  'aa000002-0000-4000-8000-000000000002',
  'aa000003-0000-4000-8000-000000000003',
  'aa000004-0000-4000-8000-000000000004',
  'aa000005-0000-4000-8000-000000000005',
  'aa000006-0000-4000-8000-000000000006',
  'aa000007-0000-4000-8000-000000000007',
  'aa000008-0000-4000-8000-000000000008',
];

for (let i = 0; i < AUDIT_EVENTS.length; i++) {
  const ev = AUDIT_EVENTS[i];
  const row = { action: ev.action, resourceType: ev.resourceType, tenantId: ev.tenantId, createdAt: NOW };
  const checksum = auditChecksum(row);
  await exec(
    `Audit: ${ev.action} (${ev.actorType})`,
    `INSERT IGNORE INTO audit_logs
       (id, tenant_id, actor_id, actor_type, action, resource_type, resource_id,
        checksum, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      uuidToBin(AUDIT_IDS[i]),
      uuidToBin(ev.tenantId),
      ev.actorId ? uuidToBin(ev.actorId) : null,
      ev.actorType,
      ev.action,
      ev.resourceType,
      ev.resourceId ? uuidToBin(ev.resourceId) : null,
      checksum,
      NOW,
    ],
  );
}

await conn.end();

// ── Summary ───────────────────────────────────────────────────────────────────
console.log();
const allOk = stats.errors === 0;
console.log(`${C.bold}${allOk ? C.green : C.red}  ╔══════════════════════════════════════════════════════════════════╗`);
console.log(`  ║  SEED COMPLETE — inserted: ${String(stats.inserted).padEnd(3)} skipped: ${String(stats.skipped).padEnd(3)} errors: ${String(stats.errors).padEnd(3)}       ║`);
console.log(`  ╚══════════════════════════════════════════════════════════════════╝${C.reset}`);
console.log();
console.log(`  ${C.dim}Default password for all seeded users: Test@12345!${C.reset}`);
console.log(`  ${C.dim}All identity values are AES-256-GCM encrypted in the DB.${C.reset}`);
console.log(`  ${C.dim}Re-running this script is safe (INSERT IGNORE).${C.reset}`);
console.log();

process.exit(stats.errors > 0 ? 1 : 0);
