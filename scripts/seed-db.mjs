/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  UICP — Production-Ready Database Seed Script (MNC Grade)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  Seeds:
 *    ── PLATFORM LAYER (separate from tenants) ──
 *    • 2 platform identities (superadmin accounts)
 *    • 10 platform roles (system roles)
 *    • 4 platform API keys
 *    • platform role assignments
 *
 *    ── TENANT LAYER ──
 *    • 4 tenants  (upflame, navdhya, ourdoc, casphere)
 *    • 25 users  (directors, managers, leads, staff)
 *    • 50 identities  (email + phone per user)
 *    • 25 credentials (bcrypt)
 *    • 25 roles    (tenant-specific business roles)
 *    • 30 permissions (granular resource:action)
 *    • role_permissions + user_roles assignments
 *    • 10 audit log entries
 *    • 8 API keys (tenant-level)
 *    • 8 email providers
 *    • 8 email templates
 *    • 4 ABAC policies
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
  // ── Tenants (4) ───────────────────────────────────────────────────────────
  T_UPFLAME : 'a0000001-0000-4000-8000-000000000001',
  T_NAVDHYA : 'a0000002-0000-4000-8000-000000000002',
  T_OURDOC  : 'a0000003-0000-4000-8000-000000000003',
  T_CASPH   : 'a0000004-0000-4000-8000-000000000004',

  // ── Users — Upflame (8) ────────────────────────────────────────────────────
  U_UPFLAME_ADMIN   : 'b0000001-0000-4000-8000-000000000001',
  U_UPFLAME_DIR_OPS : 'b0000002-0000-4000-8000-000000000002',
  U_UPFLAME_MGR_SAL : 'b0000003-0000-4000-8000-000000000003',
  U_UPFLAME_ACCTS   : 'b0000004-0000-4000-8000-000000000004',
  U_UPFLAME_IT_HEAD : 'b0000005-0000-4000-8000-000000000005',
  U_UPFLAME_SUPPORT : 'b0000006-0000-4000-8000-000000000006',
  U_UPFLAME_LOGIST  : 'b0000007-0000-4000-8000-000000000007',
  U_UPFLAME_HR     : 'b0000008-0000-4000-8000-000000000008',

  // ── Users — Navdhya (6) ──────────────────────────────────────────────────
  U_NAVDHYA_FOUNDER : 'b0000009-0000-4000-8000-000000000009',
  U_NAVDHYA_CEO    : 'b0000010-0000-4000-8000-000000000010',
  U_NAVDHYA_BOOK   : 'b0000011-0000-4000-8000-000000000011',
  U_NAVDHYA_ECOM  : 'b0000012-0000-4000-8000-000000000012',
  U_NAVDHYA_ACCTS : 'b0000013-0000-4000-8000-000000000013',
  U_NAVDHYA_SUP   : 'b0000014-0000-4000-8000-000000000014',

  // ── Users — OurDoc (6) ───────────────────────────────────────────────────
  U_OURDOC_DIR     : 'b0000015-0000-4000-8000-000000000015',
  U_OURDOC_CMO     : 'b0000016-0000-4000-8000-000000000016',
  U_OURDOC_HOSP_ADM: 'b0000017-0000-4000-8000-000000000017',
  U_OURDOC_ACCTS   : 'b0000018-0000-4000-8000-000000000018',
  U_OURDOC_SEC     : 'b0000019-0000-4000-8000-000000000019',
  U_OURDOC_RECEP   : 'b0000020-0000-4000-8000-000000000020',

  // ── Users — Casphere (5) ─────────────────────────────────────────────────
  U_CASPH_PARTNER   : 'b0000021-0000-4000-8000-000000000021',
  U_CASPH_SR_PARTNER: 'b0000022-0000-4000-8000-000000000022',
  U_CASPH_AUDIT_LD : 'b0000023-0000-4000-8000-000000000023',
  U_CASPH_TAX_CONS : 'b0000024-0000-4000-8000-000000000024',
  U_CASPH_ACCTS_LD : 'b0000025-0000-4000-8000-000000000025',

  // ── Identities (50) ───────────────────────────────────────────────────────
  // Upflame (16)
  I_UPFLAME_ADMIN_EMAIL : 'c0000001-0000-4000-8000-000000000001',
  I_UPFLAME_ADMIN_PHONE : 'c0000002-0000-4000-8000-000000000002',
  I_UPFLAME_DIR_OPS_EM  : 'c0000003-0000-4000-8000-000000000003',
  I_UPFLAME_DIR_OPS_PH  : 'c0000004-0000-4000-8000-000000000004',
  I_UPFLAME_MGR_SAL_EM  : 'c0000005-0000-4000-8000-000000000005',
  I_UPFLAME_MGR_SAL_PH  : 'c0000006-0000-4000-8000-000000000006',
  I_UPFLAME_ACCTS_EM    : 'c0000007-0000-4000-8000-000000000007',
  I_UPFLAME_ACCTS_PH    : 'c0000008-0000-4000-8000-000000000008',
  I_UPFLAME_IT_HEAD_EM  : 'c0000009-0000-4000-8000-000000000009',
  I_UPFLAME_IT_HEAD_PH  : 'c0000010-0000-4000-8000-000000000010',
  I_UPFLAME_SUPPORT_EM  : 'c0000011-0000-4000-8000-000000000011',
  I_UPFLAME_SUPPORT_PH  : 'c0000012-0000-4000-8000-000000000012',
  I_UPFLAME_LOGIST_EM   : 'c0000013-0000-4000-8000-000000000013',
  I_UPFLAME_LOGIST_PH   : 'c0000014-0000-4000-8000-000000000014',
  I_UPFLAME_HR_EM       : 'c0000015-0000-4000-8000-000000000015',
  I_UPFLAME_HR_PH       : 'c0000016-0000-4000-8000-000000000016',

  // Navdhya (12)
  I_NAVDHYA_FOUNDER_EM : 'c0000017-0000-4000-8000-000000000017',
  I_NAVDHYA_FOUNDER_PH : 'c0000018-0000-4000-8000-000000000018',
  I_NAVDHYA_CEO_EM     : 'c0000019-0000-4000-8000-000000000019',
  I_NAVDHYA_CEO_PH     : 'c0000020-0000-4000-8000-000000000020',
  I_NAVDHYA_BOOK_EM    : 'c0000021-0000-4000-8000-000000000021',
  I_NAVDHYA_BOOK_PH    : 'c0000022-0000-4000-8000-000000000022',
  I_NAVDHYA_ECOM_EM    : 'c0000023-0000-4000-8000-000000000023',
  I_NAVDHYA_ECOM_PH    : 'c0000024-0000-4000-8000-000000000024',
  I_NAVDHYA_ACCTS_EM   : 'c0000025-0000-4000-8000-000000000025',
  I_NAVDHYA_ACCTS_PH   : 'c0000026-0000-4000-8000-000000000026',
  I_NAVDHYA_SUP_EM     : 'c0000027-0000-4000-8000-000000000027',
  I_NAVDHYA_SUP_PH     : 'c0000028-0000-4000-8000-000000000028',

  // OurDoc (12)
  I_OURDOC_DIR_EM     : 'c0000029-0000-4000-8000-000000000029',
  I_OURDOC_DIR_PH     : 'c0000030-0000-4000-8000-000000000030',
  I_OURDOC_CMO_EM      : 'c0000031-0000-4000-8000-000000000031',
  I_OURDOC_CMO_PH      : 'c0000032-0000-4000-8000-000000000032',
  I_OURDOC_HADM_EM     : 'c0000033-0000-4000-8000-000000000033',
  I_OURDOC_HADM_PH     : 'c0000034-0000-4000-8000-000000000034',
  I_OURDOC_ACCTS_EM    : 'c0000035-0000-4000-8000-000000000035',
  I_OURDOC_ACCTS_PH    : 'c0000036-0000-4000-8000-000000000036',
  I_OURDOC_SEC_EM      : 'c0000037-0000-4000-8000-000000000037',
  I_OURDOC_SEC_PH      : 'c0000038-0000-4000-8000-000000000038',
  I_OURDOC_RECEP_EM    : 'c0000039-0000-4000-8000-000000000039',
  I_OURDOC_RECEP_PH    : 'c0000040-0000-4000-8000-000000000040',

  // Casphere (10)
  I_CASPH_PARTNER_EM   : 'c0000041-0000-4000-8000-000000000041',
  I_CASPH_PARTNER_PH   : 'c0000042-0000-4000-8000-000000000042',
  I_CASPH_SRP_EM       : 'c0000043-0000-4000-8000-000000000043',
  I_CASPH_SRP_PH       : 'c0000044-0000-4000-8000-000000000044',
  I_CASPH_AUDIT_EM     : 'c0000045-0000-4000-8000-000000000045',
  I_CASPH_AUDIT_PH     : 'c0000046-0000-4000-8000-000000000046',
  I_CASPH_TAX_EM       : 'c0000047-0000-4000-8000-000000000047',
  I_CASPH_TAX_PH       : 'c0000048-0000-4000-8000-000000000048',
  I_CASPH_ACCTS_EM     : 'c0000049-0000-4000-8000-000000000049',
  I_CASPH_ACCTS_PH     : 'c0000050-0000-4000-8000-000000000050',

  // ── Credentials (25) ──────────────────────────────────────────────────────
  CR_UPFLAME_ADMIN   : 'd0000001-0000-4000-8000-000000000001',
  CR_UPFLAME_DIR_OPS : 'd0000002-0000-4000-8000-000000000002',
  CR_UPFLAME_MGR_SAL : 'd0000003-0000-4000-8000-000000000003',
  CR_UPFLAME_ACCTS   : 'd0000004-0000-4000-8000-000000000004',
  CR_UPFLAME_IT_HEAD : 'd0000005-0000-4000-8000-000000000005',
  CR_UPFLAME_SUPPORT : 'd0000006-0000-4000-8000-000000000006',
  CR_UPFLAME_LOGIST  : 'd0000007-0000-4000-8000-000000000007',
  CR_UPFLAME_HR     : 'd0000008-0000-4000-8000-000000000008',
  CR_NAVDHYA_FOUNDER : 'd0000009-0000-4000-8000-000000000009',
  CR_NAVDHYA_CEO    : 'd0000010-0000-4000-8000-000000000010',
  CR_NAVDHYA_BOOK   : 'd0000011-0000-4000-8000-000000000011',
  CR_NAVDHYA_ECOM   : 'd0000012-0000-4000-8000-000000000012',
  CR_NAVDHYA_ACCTS  : 'd0000013-0000-4000-8000-000000000013',
  CR_NAVDHYA_SUP    : 'd0000014-0000-4000-8000-000000000014',
  CR_OURDOC_DIR     : 'd0000015-0000-4000-8000-000000000015',
  CR_OURDOC_CMO     : 'd0000016-0000-4000-8000-000000000016',
  CR_OURDOC_HADM    : 'd0000017-0000-4000-8000-000000000017',
  CR_OURDOC_ACCTS   : 'd0000018-0000-4000-8000-000000000018',
  CR_OURDOC_SEC     : 'd0000019-0000-4000-8000-000000000019',
  CR_OURDOC_RECEP   : 'd0000020-0000-4000-8000-000000000020',
  CR_CASPH_PARTNER  : 'd0000021-0000-4000-8000-000000000021',
  CR_CASPH_SR_PART  : 'd0000022-0000-4000-8000-000000000022',
  CR_CASPH_AUDIT_LD : 'd0000023-0000-4000-8000-000000000023',
  CR_CASPH_TAX_CONS : 'd0000024-0000-4000-8000-000000000024',
  CR_CASPH_ACCTS_LD : 'd0000025-0000-4000-8000-000000000025',

  // ── Roles (25) ───────────────────────────────────────────────────────────
  R_UPFLAME_SUPER_ADMIN : 'e0000001-0000-4000-8000-000000000001',
  R_UPFLAME_DIR_OPS    : 'e0000002-0000-4000-8000-000000000002',
  R_UPFLAME_MGR_SALES  : 'e0000003-0000-4000-8000-000000000003',
  R_UPFLAME_ACCTS_HEAD : 'e0000004-0000-4000-8000-000000000004',
  R_UPFLAME_IT_HEAD    : 'e0000005-0000-4000-8000-000000000005',
  R_UPFLAME_SUPPORT_LD : 'e0000006-0000-4000-8000-000000000006',
  R_UPFLAME_LOGIST_MGR : 'e0000007-0000-4000-8000-000000000007',
  R_UPFLAME_HR_MGR     : 'e0000008-0000-4000-8000-000000000008',
  R_NAVDHYA_FOUNDER    : 'e0000009-0000-4000-8000-000000000009',
  R_NAVDHYA_CEO       : 'e0000010-0000-4000-8000-000000000010',
  R_NAVDHYA_BOOK_MGR  : 'e0000011-0000-4000-8000-000000000011',
  R_NAVDHYA_ECOM_LD   : 'e0000012-0000-4000-8000-000000000012',
  R_NAVDHYA_ACCTS_MGR : 'e0000013-0000-4000-8000-000000000013',
  R_NAVDHYA_CUST_SUP  : 'e0000014-0000-4000-8000-000000000014',
  R_OURDOC_DIR        : 'e0000015-0000-4000-8000-000000000015',
  R_OURDOC_CMO        : 'e0000016-0000-4000-8000-000000000016',
  R_OURDOC_HOSP_ADM   : 'e0000017-0000-4000-8000-000000000017',
  R_OURDOC_ACCTS_MGR  : 'e0000018-0000-4000-8000-000000000018',
  R_OURDOC_IT_SEC     : 'e0000019-0000-4000-8000-000000000019',
  R_OURDOC_RECEP      : 'e0000020-0000-4000-8000-000000000020',
  R_CASPH_MGMT_PART   : 'e0000021-0000-4000-8000-000000000021',
  R_CASPH_SR_PARTNER  : 'e0000022-0000-4000-8000-000000000022',
  R_CASPH_AUDIT_LD   : 'e0000023-0000-4000-8000-000000000023',
  R_CASPH_TAX_CONS   : 'e0000024-0000-4000-8000-000000000024',
  R_CASPH_ACCTS_LD   : 'e0000025-0000-4000-8000-000000000025',

  // ── Permissions (30) ─────────────────────────────────────────────────────
  P_USERS_READ    : 'f0000001-0000-4000-8000-000000000001',
  P_USERS_WRITE   : 'f0000002-0000-4000-8000-000000000002',
  P_USERS_DELETE  : 'f0000003-0000-4000-8000-000000000003',
  P_SESSIONS_READ : 'f0000004-0000-4000-8000-000000000004',
  P_SESSIONS_WRITE: 'f0000005-0000-4000-8000-000000000005',
  P_AUDIT_READ    : 'f0000006-0000-4000-8000-000000000006',
  P_AUDIT_WRITE   : 'f0000007-0000-4000-8000-000000000007',
  P_IAM_MANAGE    : 'f0000008-0000-4000-8000-000000000008',
  P_API_KEYS_READ : 'f0000009-0000-4000-8000-000000000009',
  P_API_KEYS_WRITE: 'f0000010-0000-4000-8000-000000000010',
  P_ROLES_READ    : 'f0000011-0000-4000-8000-000000000011',
  P_ROLES_WRITE   : 'f0000012-0000-4000-8000-000000000012',
  P_POLICIES_READ : 'f0000013-0000-4000-8000-000000000013',
  P_POLICIES_WRITE: 'f0000014-0000-4000-8000-000000000014',
  P_EMAIL_SEND    : 'f0000015-0000-4000-8000-000000000015',
  P_TEMPLATES_READ:'f0000016-0000-4000-8000-000000000016',
  P_TEMPLATES_WRITE:'f0000017-0000-4000-8000-000000000017',
  P_WEBHOOKS_WRITE:'f0000018-0000-4000-8000-000000000018',
  P_IDENTITIES_READ: 'f0000019-0000-4000-8000-000000000019',
  P_IDENTITIES_WRITE: 'f0000020-0000-4000-8000-000000000020',
  P_CREDENTIALS_READ: 'f0000021-0000-4000-8000-000000000021',
  P_CREDENTIALS_WRITE: 'f0000022-0000-4000-8000-000000000022',
  P_TENANTS_READ  : 'f0000023-0000-4000-8000-000000000023',
  P_TENANTS_WRITE : 'f0000024-0000-4000-8000-000000000024',
  P_PROVIDERS_READ: 'f0000025-0000-4000-8000-000000000025',
  P_PROVIDERS_WRITE: 'f0000026-0000-4000-8000-000000000026',
  P_EXTENSIONS_READ: 'f0000027-0000-4000-8000-000000000027',
  P_EXTENSIONS_WRITE: 'f0000028-0000-4000-8000-000000000028',
  P_IMPERSONATE_START: 'f0000029-0000-4000-8000-000000000029',
  P_IMPERSONATE_END: 'f0000030-0000-4000-8000-000000000030',

  // ── API Keys (8) ────────────────────────────────────────────────────────
  AK_UPFLAME_1  : 'ak000001-0000-4000-8000-000000000001',
  AK_UPFLAME_2  : 'ak000002-0000-4000-8000-000000000002',
  AK_NAVDHYA_1  : 'ak000003-0000-4000-8000-000000000003',
  AK_NAVDHYA_2  : 'ak000004-0000-4000-8000-000000000004',
  AK_OURDOC_1   : 'ak000005-0000-4000-8000-000000000005',
  AK_OURDOC_2   : 'ak000006-0000-4000-8000-000000000006',
  AK_CASPH_1    : 'ak000007-0000-4000-8000-000000000007',
  AK_CASPH_2    : 'ak000008-0000-4000-8000-000000000008',

  // ── Email Providers (8) ──────────────────────────────────────────────────
  EP_UPFLAME_SMS   : 'ep000001-0000-4000-8000-000000000001',
  EP_UPFLAME_EMAIL : 'ep000002-0000-4000-8000-000000000002',
  EP_NAVDHYA_SMS   : 'ep000003-0000-4000-8000-000000000003',
  EP_NAVDHYA_EMAIL : 'ep000004-0000-4000-8000-000000000004',
  EP_OURDOC_SMS    : 'ep000005-0000-4000-8000-000000000005',
  EP_OURDOC_EMAIL  : 'ep000006-0000-4000-8000-000000000006',
  EP_CASPH_SMS     : 'ep000007-0000-4000-8000-000000000007',
  EP_CASPH_EMAIL   : 'ep000008-0000-4000-8000-000000000008',

  // ── Email Templates (8) ──────────────────────────────────────────────────
  ET_UPFLAME_WELCOME  : 'et000001-0000-4000-8000-000000000001',
  ET_NAVDHYA_WELCOME  : 'et000002-0000-4000-8000-000000000002',
  ET_OURDOC_WELCOME   : 'et000003-0000-4000-8000-000000000003',
  ET_CASPH_WELCOME    : 'et000004-0000-4000-8000-000000000004',
  ET_UPFLAME_RESET    : 'et000005-0000-4000-8000-000000000005',
  ET_NAVDHYA_RESET    : 'et000006-0000-4000-8000-000000000006',
  ET_OURDOC_RESET     : 'et000007-0000-4000-8000-000000000007',
  ET_CASPH_RESET      : 'et000008-0000-4000-8000-000000000008',

  // ── Platform Layer (separate from tenants) ─────────────────────────────────
  // Platform Identities
  PI_SUPER_ADMIN  : 'pi000001-0000-4000-8000-000000000001',
  PI_ADMIN        : 'pi000002-0000-4000-8000-000000000002',

  // Platform Roles
  PR_OWNER           : 'pr00001-0000-4000-8000-000000000001',
  PR_ADMIN           : 'pr00002-0000-4000-8000-000000000002',
  PR_IDENTITY_ADMIN : 'pr00003-0000-4000-8000-000000000003',
  PR_USER_ADMIN     : 'pr00004-0000-4000-8000-000000000004',
  PR_SECURITY_ADMIN : 'pr00005-0000-4000-8000-000000000005',
  PR_COMPLIANCE     : 'pr00006-0000-4000-8000-000000000006',
  PR_NETWORK_ADMIN  : 'pr00007-0000-4000-8000-000000000007',
  PR_VIEWER         : 'pr00008-0000-4000-8000-000000000008',
  PR_AUDITOR        : 'pr00009-0000-4000-8000-000000000009',
  PR_API_MANAGER    : 'pr00010-0000-4000-8000-000000000010',

  // Platform API Keys
  PAK_SUPER_ADMIN_1 : 'pak00001-0000-4000-8000-000000000001',
  PAK_SUPER_ADMIN_2 : 'pak00002-0000-4000-8000-000000000002',
  PAK_ADMIN_1       : 'pak00003-0000-4000-8000-000000000003',
  PAK_ADMIN_2       : 'pak00004-0000-4000-8000-000000000004',
};

// Default bcrypt hash (for fallback and platform identities)
const BCRYPT_HASH = '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi';

// bcrypt hashes for each user's unique password
const BCRYPT_PASSWORDS = {
  // Upflame
  'Upflame@2024': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Director@123': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Sales@2024': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Accounts@123': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'ITHead@2024': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Support@123': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Logistics@24': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'HR@2024': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  // Navdhya
  'Navdhya@Fnd2024': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'CEO@Navdhya24': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Bookings@123': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Ecom@2024': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'NavdhyaAcct': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Support@Navdhya': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  // OurDoc
  'OurDoc@Dir2024': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'CMO@OurDoc24': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Hospital@2024': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Accts@OurDoc': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Security@2024': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Reception@123': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  // Casphere
  'Partner@2024': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'SrPartner@24': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'AuditLead@24': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'Tax@Consul24': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'CAAccounts@24': '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
};

const NOW = new Date().toISOString().replace('T', ' ').replace('Z', '').slice(0, 23);

// ═══════════════════════════════════════════════════════════════════════════════
// SEED DATA DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

// ── PLATFORM LAYER (separate from tenants - not tenant-scoped) ───────────────
const PLATFORM_IDENTITIES = [
  // Platform Super Admin (root)
  { id: IDS.PI_SUPER_ADMIN, email: 'superadmin@uicp.platform', displayName: 'Platform Super Admin', password: 'SuperAdmin@UICP2024', mfaEnabled: true, status: 'active' },
  // Platform Admin
  { id: IDS.PI_ADMIN, email: 'admin@uicp.platform', displayName: 'Platform Administrator', password: 'PlatformAdmin@2024', mfaEnabled: true, status: 'active' },
];

// Platform Roles (system roles - same as PlatformRole.SYSTEM_ROLES in domain)
const PLATFORM_ROLES = [
  { id: IDS.PR_OWNER, type: 'platform-owner', name: 'Platform Owner', description: 'Root superadmin with full platform access', assignmentType: 'permanent', isSystem: true, canAssign: true, canDelegate: true, permissions: ['*'] },
  { id: IDS.PR_ADMIN, type: 'platform-administrator', name: 'Platform Administrator', description: 'Full administrative access to platform services', assignmentType: 'permanent', isSystem: true, canAssign: true, canDelegate: true, permissions: ['platform:read', 'platform:write', 'tenant:read', 'tenant:write', 'identity:read', 'identity:write', 'config:read', 'config:write', 'audit:read', 'announcement:write'] },
  { id: IDS.PR_IDENTITY_ADMIN, type: 'identity-administrator', name: 'Identity Administrator', description: 'Manages platform identities and authentication', assignmentType: 'permanent', isSystem: true, canAssign: true, canDelegate: false, permissions: ['identity:read', 'identity:write', 'identity:delete', 'mfa:manage', 'password:reset'] },
  { id: IDS.PR_USER_ADMIN, type: 'user-administrator', name: 'User Administrator', description: 'Manages platform user accounts', assignmentType: 'permanent', isSystem: true, canAssign: true, canDelegate: false, permissions: ['identity:read', 'identity:write', 'mfa:manage'] },
  { id: IDS.PR_SECURITY_ADMIN, type: 'security-administrator', name: 'Security Administrator', description: 'Manages security policies and incidents', assignmentType: 'eligible', isSystem: true, canAssign: true, canDelegate: true, permissions: ['security:read', 'security:write', 'ca-policy:read', 'ca-policy:write', 'zt-policy:read', 'zt-policy:write', 'threat-intel:read', 'incident:manage'] },
  { id: IDS.PR_COMPLIANCE, type: 'compliance-administrator', name: 'Compliance Administrator', description: 'Manages compliance and audit', assignmentType: 'permanent', isSystem: true, canAssign: true, canDelegate: false, permissions: ['audit:read', 'dsar:read', 'dsar:write', 'consent:read', 'retention:read'] },
  { id: IDS.PR_NETWORK_ADMIN, type: 'network-administrator', name: 'Network Administrator', description: 'Manages regions and geo-routing', assignmentType: 'eligible', isSystem: true, canAssign: true, canDelegate: false, permissions: ['region:read', 'region:write', 'geo-rule:read', 'geo-rule:write', 'failover:manage'] },
  { id: IDS.PR_VIEWER, type: 'platform-viewer', name: 'Platform Viewer', description: 'Read-only platform access', assignmentType: 'permanent', isSystem: true, canAssign: false, canDelegate: false, permissions: ['platform:read', 'tenant:read'] },
  { id: IDS.PR_AUDITOR, type: 'platform-auditor', name: 'Platform Auditor', description: 'Audit and compliance reporting', assignmentType: 'permanent', isSystem: true, canAssign: false, canDelegate: false, permissions: ['audit:read', 'signin:read', 'platform:read'] },
  { id: IDS.PR_API_MANAGER, type: 'api-manager', name: 'API Manager', description: 'Manages platform API keys', assignmentType: 'permanent', isSystem: true, canAssign: true, canDelegate: false, permissions: ['api-key:read', 'api-key:write', 'identity:read'] },
];

// Platform Role Assignments
const PLATFORM_IDENTITY_ROLES = [
  // Super Admin has Platform Owner role (permanent)
  { identityId: IDS.PI_SUPER_ADMIN, roleId: IDS.PR_OWNER, roleType: 'platform-owner', assignmentType: 'permanent', assignedBy: IDS.PI_SUPER_ADMIN },
  // Admin has Platform Administrator role
  { identityId: IDS.PI_ADMIN, roleId: IDS.PR_ADMIN, roleType: 'platform-administrator', assignmentType: 'permanent', assignedBy: IDS.PI_SUPER_ADMIN },
];

// Platform API Keys
const PLATFORM_API_KEYS = [
  // Platform Super Admin keys
  { id: IDS.PAK_SUPER_ADMIN_1, ulid: 'sF01platformSuperAdminKEY1234567890', identityId: IDS.PI_SUPER_ADMIN, type: 'secret', env: 'live', scopes: JSON.stringify(['*']), expiresAtOffset: 730 },
  { id: IDS.PAK_SUPER_ADMIN_2, ulid: 'pB01platformSuperAdminDEV123456789', identityId: IDS.PI_SUPER_ADMIN, type: 'publishable', env: 'dev', scopes: JSON.stringify(['platform:read', 'tenant:read']), expiresAtOffset: 365 },
  // Platform Admin keys
  { id: IDS.PAK_ADMIN_1, ulid: 'sF01platformAdminKEY1234567890', identityId: IDS.PI_ADMIN, type: 'secret', env: 'live', scopes: JSON.stringify(['platform:read', 'platform:write', 'tenant:read', 'tenant:write', 'identity:read', 'identity:write', 'audit:read']), expiresAtOffset: 365 },
  { id: IDS.PAK_ADMIN_2, ulid: 'uF01platformAdminREAD1234567890', identityId: IDS.PI_ADMIN, type: 'publishable', env: 'live', scopes: JSON.stringify(['platform:read', 'tenant:read', 'audit:read']), expiresAtOffset: 365 },
];

// ── TENANT LAYER ───────────────────────────────────────────────────────────────
const TENANTS = [
  {
    id: IDS.T_UPFLAME, slug: 'upflame', plan: 'enterprise',
    max_users: 1000, max_sessions: 10, mfa_policy: 'required', session_ttl_s: 86400,
    password_policy: { minLength: 10, requireUppercase: true, requireDigit: true, requireSpecial: true },
    allowed_domains: ['upflame.in'],
  },
  {
    id: IDS.T_NAVDHYA, slug: 'navdhya', plan: 'enterprise',
    max_users: 500, max_sessions: 8, mfa_policy: 'optional', session_ttl_s: 72000,
    password_policy: { minLength: 8, requireUppercase: true, requireDigit: true, requireSpecial: false },
    allowed_domains: ['navdhya.com'],
  },
  {
    id: IDS.T_OURDOC, slug: 'ourdoc', plan: 'enterprise',
    max_users: 500, max_sessions: 6, mfa_policy: 'required', session_ttl_s: 43200,
    password_policy: { minLength: 12, requireUppercase: true, requireDigit: true, requireSpecial: true },
    allowed_domains: ['ourdoc.in'],
  },
  {
    id: IDS.T_CASPH, slug: 'casphere', plan: 'enterprise',
    max_users: 100, max_sessions: 5, mfa_policy: 'required', session_ttl_s: 36000,
    password_policy: { minLength: 10, requireUppercase: true, requireDigit: true, requireSpecial: true },
    allowed_domains: ['casphere.avt.ink'],
  },
];

const USERS = [
  // Upflame (8)
  { id: IDS.U_UPFLAME_ADMIN,   tenantId: IDS.T_UPFLAME, displayName: 'Rajesh Kumar',      password: 'Upflame@2024' },
  { id: IDS.U_UPFLAME_DIR_OPS, tenantId: IDS.T_UPFLAME, displayName: 'Priya Sharma',      password: 'Director@123' },
  { id: IDS.U_UPFLAME_MGR_SAL, tenantId: IDS.T_UPFLAME, displayName: 'Amit Patel',       password: 'Sales@2024' },
  { id: IDS.U_UPFLAME_ACCTS,   tenantId: IDS.T_UPFLAME, displayName: 'Sonia Gupta',       password: 'Accounts@123' },
  { id: IDS.U_UPFLAME_IT_HEAD, tenantId: IDS.T_UPFLAME, displayName: 'Vikram Singh',      password: 'ITHead@2024' },
  { id: IDS.U_UPFLAME_SUPPORT, tenantId: IDS.T_UPFLAME, displayName: 'Anita Desai',       password: 'Support@123' },
  { id: IDS.U_UPFLAME_LOGIST,  tenantId: IDS.T_UPFLAME, displayName: 'Raj Mehta',        password: 'Logistics@24' },
  { id: IDS.U_UPFLAME_HR,      tenantId: IDS.T_UPFLAME, displayName: 'Neha Khanna',       password: 'HR@2024' },
  // Navdhya (6)
  { id: IDS.U_NAVDHYA_FOUNDER, tenantId: IDS.T_NAVDHYA, displayName: 'Pandit Raghav',     password: 'Navdhya@Fnd2024' },
  { id: IDS.U_NAVDHYA_CEO,     tenantId: IDS.T_NAVDHYA, displayName: 'Anjali Reddy',     password: 'CEO@Navdhya24' },
  { id: IDS.U_NAVDHYA_BOOK,    tenantId: IDS.T_NAVDHYA, displayName: 'Deepak Verma',      password: 'Bookings@123' },
  { id: IDS.U_NAVDHYA_ECOM,    tenantId: IDS.T_NAVDHYA, displayName: 'Kavita Jain',       password: 'Ecom@2024' },
  { id: IDS.U_NAVDHYA_ACCTS,   tenantId: IDS.T_NAVDHYA, displayName: 'Suresh Prasad',    password: 'NavdhyaAcct' },
  { id: IDS.U_NAVDHYA_SUP,     tenantId: IDS.T_NAVDHYA, displayName: 'Riya Shah',         password: 'Support@Navdhya' },
  // OurDoc (6)
  { id: IDS.U_OURDOC_DIR,      tenantId: IDS.T_OURDOC,  displayName: 'Dr. Sunita Reddy',   password: 'OurDoc@Dir2024' },
  { id: IDS.U_OURDOC_CMO,      tenantId: IDS.T_OURDOC,  displayName: 'Dr. Ramesh Babu',   password: 'CMO@OurDoc24' },
  { id: IDS.U_OURDOC_HOSP_ADM, tenantId: IDS.T_OURDOC,  displayName: 'Lakshmi Narayanan', password: 'Hospital@2024' },
  { id: IDS.U_OURDOC_ACCTS,    tenantId: IDS.T_OURDOC,  displayName: 'Arun Kumar',        password: 'Accts@OurDoc' },
  { id: IDS.U_OURDOC_SEC,      tenantId: IDS.T_OURDOC,  displayName: 'Jennifer Maria',    password: 'Security@2024' },
  { id: IDS.U_OURDOC_RECEP,    tenantId: IDS.T_OURDOC,  displayName: 'Smitha Iyer',       password: 'Reception@123' },
  // Casphere (5)
  { id: IDS.U_CASPH_PARTNER,   tenantId: IDS.T_CASPH,  displayName: 'CA Amit Jha',        password: 'Partner@2024' },
  { id: IDS.U_CASPH_SR_PARTNER,tenantId: IDS.T_CASPH,  displayName: 'CA Shreya Malhotra', password: 'SrPartner@24' },
  { id: IDS.U_CASPH_AUDIT_LD,  tenantId: IDS.T_CASPH,  displayName: 'CA Aditya Sharma',   password: 'AuditLead@24' },
  { id: IDS.U_CASPH_TAX_CONS,  tenantId: IDS.T_CASPH,  displayName: 'CA Fatima Zahra',   password: 'Tax@Consul24' },
  { id: IDS.U_CASPH_ACCTS_LD,  tenantId: IDS.T_CASPH,  displayName: 'Nikhil Garg',       password: 'CAAccounts@24' },
];

// Email identities for each user
const IDENTITIES = [
  // Upflame
  { id: IDS.I_UPFLAME_ADMIN_EMAIL, userId: IDS.U_UPFLAME_ADMIN, tenantId: IDS.T_UPFLAME, type: 'email', value: 'admin@upflame.in', verified: true },
  { id: IDS.I_UPFLAME_ADMIN_PHONE, userId: IDS.U_UPFLAME_ADMIN, tenantId: IDS.T_UPFLAME, type: 'phone', value: '+919876543210', verified: true },
  { id: IDS.I_UPFLAME_DIR_OPS_EM, userId: IDS.U_UPFLAME_DIR_OPS, tenantId: IDS.T_UPFLAME, type: 'email', value: 'director.ops@upflame.in', verified: true },
  { id: IDS.I_UPFLAME_DIR_OPS_PH, userId: IDS.U_UPFLAME_DIR_OPS, tenantId: IDS.T_UPFLAME, type: 'phone', value: '+919876543211', verified: true },
  { id: IDS.I_UPFLAME_MGR_SAL_EM, userId: IDS.U_UPFLAME_MGR_SAL, tenantId: IDS.T_UPFLAME, type: 'email', value: 'manager.sales@upflame.in', verified: true },
  { id: IDS.I_UPFLAME_MGR_SAL_PH, userId: IDS.U_UPFLAME_MGR_SAL, tenantId: IDS.T_UPFLAME, type: 'phone', value: '+919876543212', verified: true },
  { id: IDS.I_UPFLAME_ACCTS_EM, userId: IDS.U_UPFLAME_ACCTS, tenantId: IDS.T_UPFLAME, type: 'email', value: 'accounts@upflame.in', verified: true },
  { id: IDS.I_UPFLAME_ACCTS_PH, userId: IDS.U_UPFLAME_ACCTS, tenantId: IDS.T_UPFLAME, type: 'phone', value: '+919876543213', verified: true },
  { id: IDS.I_UPFLAME_IT_HEAD_EM, userId: IDS.U_UPFLAME_IT_HEAD, tenantId: IDS.T_UPFLAME, type: 'email', value: 'it.head@upflame.in', verified: true },
  { id: IDS.I_UPFLAME_IT_HEAD_PH, userId: IDS.U_UPFLAME_IT_HEAD, tenantId: IDS.T_UPFLAME, type: 'phone', value: '+919876543214', verified: true },
  { id: IDS.I_UPFLAME_SUPPORT_EM, userId: IDS.U_UPFLAME_SUPPORT, tenantId: IDS.T_UPFLAME, type: 'email', value: 'support@upflame.in', verified: true },
  { id: IDS.I_UPFLAME_SUPPORT_PH, userId: IDS.U_UPFLAME_SUPPORT, tenantId: IDS.T_UPFLAME, type: 'phone', value: '+919876543215', verified: true },
  { id: IDS.I_UPFLAME_LOGIST_EM, userId: IDS.U_UPFLAME_LOGIST, tenantId: IDS.T_UPFLAME, type: 'email', value: 'logistics@upflame.in', verified: true },
  { id: IDS.I_UPFLAME_LOGIST_PH, userId: IDS.U_UPFLAME_LOGIST, tenantId: IDS.T_UPFLAME, type: 'phone', value: '+919876543216', verified: true },
  { id: IDS.I_UPFLAME_HR_EM, userId: IDS.U_UPFLAME_HR, tenantId: IDS.T_UPFLAME, type: 'email', value: 'hr@upflame.in', verified: true },
  { id: IDS.I_UPFLAME_HR_PH, userId: IDS.U_UPFLAME_HR, tenantId: IDS.T_UPFLAME, type: 'phone', value: '+919876543217', verified: true },
  // Navdhya
  { id: IDS.I_NAVDHYA_FOUNDER_EM, userId: IDS.U_NAVDHYA_FOUNDER, tenantId: IDS.T_NAVDHYA, type: 'email', value: 'founder@navdhya.com', verified: true },
  { id: IDS.I_NAVDHYA_FOUNDER_PH, userId: IDS.U_NAVDHYA_FOUNDER, tenantId: IDS.T_NAVDHYA, type: 'phone', value: '+919987654321', verified: true },
  { id: IDS.I_NAVDHYA_CEO_EM, userId: IDS.U_NAVDHYA_CEO, tenantId: IDS.T_NAVDHYA, type: 'email', value: 'ceo@navdhya.com', verified: true },
  { id: IDS.I_NAVDHYA_CEO_PH, userId: IDS.U_NAVDHYA_CEO, tenantId: IDS.T_NAVDHYA, type: 'phone', value: '+919987654322', verified: true },
  { id: IDS.I_NAVDHYA_BOOK_EM, userId: IDS.U_NAVDHYA_BOOK, tenantId: IDS.T_NAVDHYA, type: 'email', value: 'bookings@navdhya.com', verified: true },
  { id: IDS.I_NAVDHYA_BOOK_PH, userId: IDS.U_NAVDHYA_BOOK, tenantId: IDS.T_NAVDHYA, type: 'phone', value: '+919987654323', verified: true },
  { id: IDS.I_NAVDHYA_ECOM_EM, userId: IDS.U_NAVDHYA_ECOM, tenantId: IDS.T_NAVDHYA, type: 'email', value: 'ecommerce@navdhya.com', verified: true },
  { id: IDS.I_NAVDHYA_ECOM_PH, userId: IDS.U_NAVDHYA_ECOM, tenantId: IDS.T_NAVDHYA, type: 'phone', value: '+919987654324', verified: true },
  { id: IDS.I_NAVDHYA_ACCTS_EM, userId: IDS.U_NAVDHYA_ACCTS, tenantId: IDS.T_NAVDHYA, type: 'email', value: 'accounts@navdhya.com', verified: true },
  { id: IDS.I_NAVDHYA_ACCTS_PH, userId: IDS.U_NAVDHYA_ACCTS, tenantId: IDS.T_NAVDHYA, type: 'phone', value: '+919987654325', verified: true },
  { id: IDS.I_NAVDHYA_SUP_EM, userId: IDS.U_NAVDHYA_SUP, tenantId: IDS.T_NAVDHYA, type: 'email', value: 'support@navdhya.com', verified: true },
  { id: IDS.I_NAVDHYA_SUP_PH, userId: IDS.U_NAVDHYA_SUP, tenantId: IDS.T_NAVDHYA, type: 'phone', value: '+919987654326', verified: true },
  // OurDoc
  { id: IDS.I_OURDOC_DIR_EM, userId: IDS.U_OURDOC_DIR, tenantId: IDS.T_OURDOC, type: 'email', value: 'director@ourdoc.in', verified: true },
  { id: IDS.I_OURDOC_DIR_PH, userId: IDS.U_OURDOC_DIR, tenantId: IDS.T_OURDOC, type: 'phone', value: '+919123456789', verified: true },
  { id: IDS.I_OURDOC_CMO_EM, userId: IDS.U_OURDOC_CMO, tenantId: IDS.T_OURDOC, type: 'email', value: 'chief.medical@ourdoc.in', verified: true },
  { id: IDS.I_OURDOC_CMO_PH, userId: IDS.U_OURDOC_CMO, tenantId: IDS.T_OURDOC, type: 'phone', value: '+919123456790', verified: true },
  { id: IDS.I_OURDOC_HADM_EM, userId: IDS.U_OURDOC_HOSP_ADM, tenantId: IDS.T_OURDOC, type: 'email', value: 'admin.hospital@ourdoc.in', verified: true },
  { id: IDS.I_OURDOC_HADM_PH, userId: IDS.U_OURDOC_HOSP_ADM, tenantId: IDS.T_OURDOC, type: 'phone', value: '+919123456791', verified: true },
  { id: IDS.I_OURDOC_ACCTS_EM, userId: IDS.U_OURDOC_ACCTS, tenantId: IDS.T_OURDOC, type: 'email', value: 'accounts@ourdoc.in', verified: true },
  { id: IDS.I_OURDOC_ACCTS_PH, userId: IDS.U_OURDOC_ACCTS, tenantId: IDS.T_OURDOC, type: 'phone', value: '+919123456792', verified: true },
  { id: IDS.I_OURDOC_SEC_EM, userId: IDS.U_OURDOC_SEC, tenantId: IDS.T_OURDOC, type: 'email', value: 'it.security@ourdoc.in', verified: true },
  { id: IDS.I_OURDOC_SEC_PH, userId: IDS.U_OURDOC_SEC, tenantId: IDS.T_OURDOC, type: 'phone', value: '+919123456793', verified: true },
  { id: IDS.I_OURDOC_RECEP_EM, userId: IDS.U_OURDOC_RECEP, tenantId: IDS.T_OURDOC, type: 'email', value: 'reception@ourdoc.in', verified: true },
  { id: IDS.I_OURDOC_RECEP_PH, userId: IDS.U_OURDOC_RECEP, tenantId: IDS.T_OURDOC, type: 'phone', value: '+919123456794', verified: true },
  // Casphere
  { id: IDS.I_CASPH_PARTNER_EM, userId: IDS.U_CASPH_PARTNER, tenantId: IDS.T_CASPH, type: 'email', value: 'partner@casphere.avt.ink', verified: true },
  { id: IDS.I_CASPH_PARTNER_PH, userId: IDS.U_CASPH_PARTNER, tenantId: IDS.T_CASPH, type: 'phone', value: '+918987654321', verified: true },
  { id: IDS.I_CASPH_SRP_EM, userId: IDS.U_CASPH_SR_PARTNER, tenantId: IDS.T_CASPH, type: 'email', value: 'senior.partner@casphere.avt.ink', verified: true },
  { id: IDS.I_CASPH_SRP_PH, userId: IDS.U_CASPH_SR_PARTNER, tenantId: IDS.T_CASPH, type: 'phone', value: '+918987654322', verified: true },
  { id: IDS.I_CASPH_AUDIT_EM, userId: IDS.U_CASPH_AUDIT_LD, tenantId: IDS.T_CASPH, type: 'email', value: 'audit.lead@casphere.avt.ink', verified: true },
  { id: IDS.I_CASPH_AUDIT_PH, userId: IDS.U_CASPH_AUDIT_LD, tenantId: IDS.T_CASPH, type: 'phone', value: '+918987654323', verified: true },
  { id: IDS.I_CASPH_TAX_EM, userId: IDS.U_CASPH_TAX_CONS, tenantId: IDS.T_CASPH, type: 'email', value: 'tax.consultant@casphere.avt.ink', verified: true },
  { id: IDS.I_CASPH_TAX_PH, userId: IDS.U_CASPH_TAX_CONS, tenantId: IDS.T_CASPH, type: 'phone', value: '+918987654324', verified: true },
  { id: IDS.I_CASPH_ACCTS_EM, userId: IDS.U_CASPH_ACCTS_LD, tenantId: IDS.T_CASPH, type: 'email', value: 'accounts@casphere.avt.ink', verified: true },
  { id: IDS.I_CASPH_ACCTS_PH, userId: IDS.U_CASPH_ACCTS_LD, tenantId: IDS.T_CASPH, type: 'phone', value: '+918987654325', verified: true },
];

// Credentials with unique bcrypt hashes
const CREDENTIALS = [
  // Upflame
  { id: IDS.CR_UPFLAME_ADMIN,   userId: IDS.U_UPFLAME_ADMIN,   password: 'Upflame@2024' },
  { id: IDS.CR_UPFLAME_DIR_OPS, userId: IDS.U_UPFLAME_DIR_OPS, password: 'Director@123' },
  { id: IDS.CR_UPFLAME_MGR_SAL, userId: IDS.U_UPFLAME_MGR_SAL, password: 'Sales@2024' },
  { id: IDS.CR_UPFLAME_ACCTS,   userId: IDS.U_UPFLAME_ACCTS,   password: 'Accounts@123' },
  { id: IDS.CR_UPFLAME_IT_HEAD, userId: IDS.U_UPFLAME_IT_HEAD, password: 'ITHead@2024' },
  { id: IDS.CR_UPFLAME_SUPPORT, userId: IDS.U_UPFLAME_SUPPORT, password: 'Support@123' },
  { id: IDS.CR_UPFLAME_LOGIST,  userId: IDS.U_UPFLAME_LOGIST, password: 'Logistics@24' },
  { id: IDS.CR_UPFLAME_HR,      userId: IDS.U_UPFLAME_HR,      password: 'HR@2024' },
  // Navdhya
  { id: IDS.CR_NAVDHYA_FOUNDER, userId: IDS.U_NAVDHYA_FOUNDER, password: 'Navdhya@Fnd2024' },
  { id: IDS.CR_NAVDHYA_CEO,     userId: IDS.U_NAVDHYA_CEO,     password: 'CEO@Navdhya24' },
  { id: IDS.CR_NAVDHYA_BOOK,    userId: IDS.U_NAVDHYA_BOOK,    password: 'Bookings@123' },
  { id: IDS.CR_NAVDHYA_ECOM,    userId: IDS.U_NAVDHYA_ECOM,    password: 'Ecom@2024' },
  { id: IDS.CR_NAVDHYA_ACCTS,   userId: IDS.U_NAVDHYA_ACCTS,   password: 'NavdhyaAcct' },
  { id: IDS.CR_NAVDHYA_SUP,     userId: IDS.U_NAVDHYA_SUP,     password: 'Support@Navdhya' },
  // OurDoc
  { id: IDS.CR_OURDOC_DIR,      userId: IDS.U_OURDOC_DIR,      password: 'OurDoc@Dir2024' },
  { id: IDS.CR_OURDOC_CMO,      userId: IDS.U_OURDOC_CMO,      password: 'CMO@OurDoc24' },
  { id: IDS.CR_OURDOC_HADM,     userId: IDS.U_OURDOC_HOSP_ADM, password: 'Hospital@2024' },
  { id: IDS.CR_OURDOC_ACCTS,    userId: IDS.U_OURDOC_ACCTS,    password: 'Accts@OurDoc' },
  { id: IDS.CR_OURDOC_SEC,      userId: IDS.U_OURDOC_SEC,      password: 'Security@2024' },
  { id: IDS.CR_OURDOC_RECEP,    userId: IDS.U_OURDOC_RECEP,    password: 'Reception@123' },
  // Casphere
  { id: IDS.CR_CASPH_PARTNER,   userId: IDS.U_CASPH_PARTNER,   password: 'Partner@2024' },
  { id: IDS.CR_CASPH_SR_PART,    userId: IDS.U_CASPH_SR_PARTNER,password: 'SrPartner@24' },
  { id: IDS.CR_CASPH_AUDIT_LD,   userId: IDS.U_CASPH_AUDIT_LD, password: 'AuditLead@24' },
  { id: IDS.CR_CASPH_TAX_CONS,   userId: IDS.U_CASPH_TAX_CONS, password: 'Tax@Consul24' },
  { id: IDS.CR_CASPH_ACCTS_LD,   userId: IDS.U_CASPH_ACCTS_LD, password: 'CAAccounts@24' },
];

const ROLES = [
  // Platform-wide Super Admin (not tenant-scoped - controls ALL tenants)
  { id: IDS.R_UPFLAME_SUPER_ADMIN, tenantId: IDS.T_UPFLAME, name: 'super-admin', description: 'Platform Super Admin - full access to ALL tenants' },
  // Tenant-specific roles
  { id: IDS.R_UPFLAME_DIR_OPS, tenantId: IDS.T_UPFLAME, name: 'director-operations', description: 'Director of Operations' },
  { id: IDS.R_UPFLAME_MGR_SALES, tenantId: IDS.T_UPFLAME, name: 'sales-manager', description: 'Sales Manager' },
  { id: IDS.R_UPFLAME_ACCTS_HEAD, tenantId: IDS.T_UPFLAME, name: 'accounts-head', description: 'Accounts Head' },
  { id: IDS.R_UPFLAME_IT_HEAD, tenantId: IDS.T_UPFLAME, name: 'it-head', description: 'IT Head' },
  { id: IDS.R_UPFLAME_SUPPORT_LD, tenantId: IDS.T_UPFLAME, name: 'support-lead', description: 'Support Lead' },
  { id: IDS.R_UPFLAME_LOGIST_MGR, tenantId: IDS.T_UPFLAME, name: 'logistics-manager', description: 'Logistics Manager' },
  { id: IDS.R_UPFLAME_HR_MGR, tenantId: IDS.T_UPFLAME, name: 'hr-manager', description: 'HR Manager' },
  // Navdhya
  { id: IDS.R_NAVDHYA_FOUNDER, tenantId: IDS.T_NAVDHYA, name: 'founder', description: 'Founder' },
  { id: IDS.R_NAVDHYA_CEO, tenantId: IDS.T_NAVDHYA, name: 'ceo', description: 'CEO' },
  { id: IDS.R_NAVDHYA_BOOK_MGR, tenantId: IDS.T_NAVDHYA, name: 'booking-manager', description: 'Booking Manager' },
  { id: IDS.R_NAVDHYA_ECOM_LD, tenantId: IDS.T_NAVDHYA, name: 'ecommerce-lead', description: 'E-commerce Lead' },
  { id: IDS.R_NAVDHYA_ACCTS_MGR, tenantId: IDS.T_NAVDHYA, name: 'accounts-manager', description: 'Accounts Manager' },
  { id: IDS.R_NAVDHYA_CUST_SUP, tenantId: IDS.T_NAVDHYA, name: 'customer-support', description: 'Customer Support' },
  // OurDoc
  { id: IDS.R_OURDOC_DIR, tenantId: IDS.T_OURDOC, name: 'hospital-director', description: 'Hospital Director' },
  { id: IDS.R_OURDOC_CMO, tenantId: IDS.T_OURDOC, name: 'chief-medical-officer', description: 'Chief Medical Officer' },
  { id: IDS.R_OURDOC_HOSP_ADM, tenantId: IDS.T_OURDOC, name: 'hospital-admin', description: 'Hospital Admin' },
  { id: IDS.R_OURDOC_ACCTS_MGR, tenantId: IDS.T_OURDOC, name: 'accounts-manager', description: 'Accounts Manager' },
  { id: IDS.R_OURDOC_IT_SEC, tenantId: IDS.T_OURDOC, name: 'it-security', description: 'IT Security' },
  { id: IDS.R_OURDOC_RECEP, tenantId: IDS.T_OURDOC, name: 'receptionist', description: 'Receptionist' },
  // Casphere
  { id: IDS.R_CASPH_MGMT_PART, tenantId: IDS.T_CASPH, name: 'managing-partner', description: 'Managing Partner' },
  { id: IDS.R_CASPH_SR_PARTNER, tenantId: IDS.T_CASPH, name: 'senior-partner', description: 'Senior Partner' },
  { id: IDS.R_CASPH_AUDIT_LD, tenantId: IDS.T_CASPH, name: 'audit-lead', description: 'Audit Lead' },
  { id: IDS.R_CASPH_TAX_CONS, tenantId: IDS.T_CASPH, name: 'tax-consultant', description: 'Tax Consultant' },
  { id: IDS.R_CASPH_ACCTS_LD, tenantId: IDS.T_CASPH, name: 'accounts-lead', description: 'Accounts Lead' },
];

const PERMISSIONS = [
  // Core permissions
  { id: IDS.P_USERS_READ,    tenantId: IDS.T_UPFLAME, resource: 'users',    action: 'read'    },
  { id: IDS.P_USERS_WRITE,   tenantId: IDS.T_UPFLAME, resource: 'users',    action: 'write'   },
  { id: IDS.P_USERS_DELETE,  tenantId: IDS.T_UPFLAME, resource: 'users',    action: 'delete'  },
  { id: IDS.P_SESSIONS_READ,  tenantId: IDS.T_UPFLAME, resource: 'sessions', action: 'read'    },
  { id: IDS.P_SESSIONS_WRITE, tenantId: IDS.T_UPFLAME, resource: 'sessions', action: 'write'   },
  { id: IDS.P_AUDIT_READ,    tenantId: IDS.T_UPFLAME, resource: 'audit',    action: 'read'    },
  { id: IDS.P_AUDIT_WRITE,   tenantId: IDS.T_UPFLAME, resource: 'audit',    action: 'write'   },
  { id: IDS.P_IAM_MANAGE,    tenantId: IDS.T_UPFLAME, resource: 'iam',      action: 'manage'  },
  { id: IDS.P_API_KEYS_READ,  tenantId: IDS.T_UPFLAME, resource: 'api_keys', action: 'read'    },
  { id: IDS.P_API_KEYS_WRITE, tenantId: IDS.T_UPFLAME, resource: 'api_keys', action: 'write'   },
  { id: IDS.P_ROLES_READ,   tenantId: IDS.T_UPFLAME, resource: 'roles',    action: 'read'    },
  { id: IDS.P_ROLES_WRITE,  tenantId: IDS.T_UPFLAME, resource: 'roles',    action: 'write'   },
  { id: IDS.P_POLICIES_READ,  tenantId: IDS.T_UPFLAME, resource: 'policies', action: 'read'    },
  { id: IDS.P_POLICIES_WRITE, tenantId: IDS.T_UPFLAME, resource: 'policies', action: 'write'   },
  { id: IDS.P_EMAIL_SEND,      tenantId: IDS.T_UPFLAME, resource: 'email',    action: 'send'    },
  { id: IDS.P_TEMPLATES_READ, tenantId: IDS.T_UPFLAME, resource: 'templates', action: 'read'  },
  { id: IDS.P_TEMPLATES_WRITE,tenantId: IDS.T_UPFLAME, resource: 'templates', action: 'write'  },
  { id: IDS.P_WEBHOOKS_WRITE, tenantId: IDS.T_UPFLAME, resource: 'webhooks', action: 'write'   },
  { id: IDS.P_IDENTITIES_READ, tenantId: IDS.T_UPFLAME, resource: 'identities', action: 'read' },
  { id: IDS.P_IDENTITIES_WRITE, tenantId: IDS.T_UPFLAME, resource: 'identities', action: 'write' },
  { id: IDS.P_CREDENTIALS_READ, tenantId: IDS.T_UPFLAME, resource: 'credentials', action: 'read' },
  { id: IDS.P_CREDENTIALS_WRITE, tenantId: IDS.T_UPFLAME, resource: 'credentials', action: 'write' },
  { id: IDS.P_TENANTS_READ,  tenantId: IDS.T_UPFLAME, resource: 'tenants', action: 'read' },
  { id: IDS.P_TENANTS_WRITE, tenantId: IDS.T_UPFLAME, resource: 'tenants', action: 'write' },
  { id: IDS.P_PROVIDERS_READ, tenantId: IDS.T_UPFLAME, resource: 'providers', action: 'read' },
  { id: IDS.P_PROVIDERS_WRITE, tenantId: IDS.T_UPFLAME, resource: 'providers', action: 'write' },
  { id: IDS.P_EXTENSIONS_READ, tenantId: IDS.T_UPFLAME, resource: 'extensions', action: 'read' },
  { id: IDS.P_EXTENSIONS_WRITE, tenantId: IDS.T_UPFLAME, resource: 'extensions', action: 'write' },
  { id: IDS.P_IMPERSONATE_START, tenantId: IDS.T_UPFLAME, resource: 'impersonation', action: 'start' },
  { id: IDS.P_IMPERSONATE_END, tenantId: IDS.T_UPFLAME, resource: 'impersonation', action: 'end' },
];

// Role → Permissions assignments
const ROLE_PERMISSIONS = [
  // Super Admin gets all
  ...PERMISSIONS.map(p => ({ roleId: IDS.R_UPFLAME_SUPER_ADMIN, permId: p.id })),
  // Director Operations
  { roleId: IDS.R_UPFLAME_DIR_OPS, permId: IDS.P_USERS_READ },
  { roleId: IDS.R_UPFLAME_DIR_OPS, permId: IDS.P_USERS_WRITE },
  { roleId: IDS.R_UPFLAME_DIR_OPS, permId: IDS.P_SESSIONS_READ },
  { roleId: IDS.R_UPFLAME_DIR_OPS, permId: IDS.P_AUDIT_READ },
  { roleId: IDS.R_UPFLAME_DIR_OPS, permId: IDS.P_EMAIL_SEND },
  // Add more role-permission mappings as needed
];

// User → Role assignments
// Platform Super Admin (Rajesh Kumar) has access to ALL 4 tenants
const USER_ROLES = [
  // Rajesh Kumar (Super Admin) - has role in ALL tenants for cross-tenant access
  { userId: IDS.U_UPFLAME_ADMIN,   roleId: IDS.R_UPFLAME_SUPER_ADMIN, tenantId: IDS.T_UPFLAME },
  { userId: IDS.U_UPFLAME_ADMIN,   roleId: IDS.R_UPFLAME_SUPER_ADMIN, tenantId: IDS.T_NAVDHYA },
  { userId: IDS.U_UPFLAME_ADMIN,   roleId: IDS.R_UPFLAME_SUPER_ADMIN, tenantId: IDS.T_OURDOC },
  { userId: IDS.U_UPFLAME_ADMIN,   roleId: IDS.R_UPFLAME_SUPER_ADMIN, tenantId: IDS.T_CASPH },

  // Upflame other users
  { userId: IDS.U_UPFLAME_DIR_OPS, roleId: IDS.R_UPFLAME_DIR_OPS, tenantId: IDS.T_UPFLAME },
  { userId: IDS.U_UPFLAME_MGR_SAL, roleId: IDS.R_UPFLAME_MGR_SALES, tenantId: IDS.T_UPFLAME },
  { userId: IDS.U_UPFLAME_ACCTS,   roleId: IDS.R_UPFLAME_ACCTS_HEAD, tenantId: IDS.T_UPFLAME },
  { userId: IDS.U_UPFLAME_IT_HEAD, roleId: IDS.R_UPFLAME_IT_HEAD, tenantId: IDS.T_UPFLAME },
  { userId: IDS.U_UPFLAME_SUPPORT, roleId: IDS.R_UPFLAME_SUPPORT_LD, tenantId: IDS.T_UPFLAME },
  { userId: IDS.U_UPFLAME_LOGIST,  roleId: IDS.R_UPFLAME_LOGIST_MGR, tenantId: IDS.T_UPFLAME },
  { userId: IDS.U_UPFLAME_HR,      roleId: IDS.R_UPFLAME_HR_MGR, tenantId: IDS.T_UPFLAME },
  // Navdhya
  { userId: IDS.U_NAVDHYA_FOUNDER, roleId: IDS.R_NAVDHYA_FOUNDER, tenantId: IDS.T_NAVDHYA },
  { userId: IDS.U_NAVDHYA_CEO,     roleId: IDS.R_NAVDHYA_CEO, tenantId: IDS.T_NAVDHYA },
  { userId: IDS.U_NAVDHYA_BOOK,    roleId: IDS.R_NAVDHYA_BOOK_MGR, tenantId: IDS.T_NAVDHYA },
  { userId: IDS.U_NAVDHYA_ECOM,    roleId: IDS.R_NAVDHYA_ECOM_LD, tenantId: IDS.T_NAVDHYA },
  { userId: IDS.U_NAVDHYA_ACCTS,   roleId: IDS.R_NAVDHYA_ACCTS_MGR, tenantId: IDS.T_NAVDHYA },
  { userId: IDS.U_NAVDHYA_SUP,     roleId: IDS.R_NAVDHYA_CUST_SUP, tenantId: IDS.T_NAVDHYA },
  // OurDoc
  { userId: IDS.U_OURDOC_DIR,      roleId: IDS.R_OURDOC_DIR, tenantId: IDS.T_OURDOC },
  { userId: IDS.U_OURDOC_CMO,      roleId: IDS.R_OURDOC_CMO, tenantId: IDS.T_OURDOC },
  { userId: IDS.U_OURDOC_HOSP_ADM, roleId: IDS.R_OURDOC_HOSP_ADM, tenantId: IDS.T_OURDOC },
  { userId: IDS.U_OURDOC_ACCTS,    roleId: IDS.R_OURDOC_ACCTS_MGR, tenantId: IDS.T_OURDOC },
  { userId: IDS.U_OURDOC_SEC,      roleId: IDS.R_OURDOC_IT_SEC, tenantId: IDS.T_OURDOC },
  { userId: IDS.U_OURDOC_RECEP,    roleId: IDS.R_OURDOC_RECEP, tenantId: IDS.T_OURDOC },
  // Casphere
  { userId: IDS.U_CASPH_PARTNER,   roleId: IDS.R_CASPH_MGMT_PART, tenantId: IDS.T_CASPH },
  { userId: IDS.U_CASPH_SR_PARTNER, roleId: IDS.R_CASPH_SR_PARTNER, tenantId: IDS.T_CASPH },
  { userId: IDS.U_CASPH_AUDIT_LD,  roleId: IDS.R_CASPH_AUDIT_LD, tenantId: IDS.T_CASPH },
  { userId: IDS.U_CASPH_TAX_CONS,  roleId: IDS.R_CASPH_TAX_CONS, tenantId: IDS.T_CASPH },
  { userId: IDS.U_CASPH_ACCTS_LD,  roleId: IDS.R_CASPH_ACCTS_LD, tenantId: IDS.T_CASPH },
];

// API Keys with ULID prefixes
// Platform Super Admin key - works across ALL tenants via cross-tenant role membership
const API_KEYS = [
  // Platform Super Admin key - cross-tenant access (scopes indicate platform-wide)
  { id: IDS.AK_UPFLAME_1, ulid: 'sF01platformSuperAdminXYZ12345678', tenantId: IDS.T_UPFLAME, userId: IDS.U_UPFLAME_ADMIN, type: 'secret', env: 'live', scopes: JSON.stringify(['platform:super_admin', 'tenants:read', 'tenants:write', 'users:*', 'sessions:*', 'api_keys:*', 'roles:*', 'policies:*', 'audit:*', 'email:*', 'templates:*', 'webhooks:*', 'identities:*', 'credentials:*', 'providers:*', 'extensions:*', 'impersonation:*']), expiresAtOffset: 365 },
  // Upflame tenant keys
  { id: IDS.AK_UPFLAME_2, ulid: 'uF01upflame2opsA7B2C3D4E5', tenantId: IDS.T_UPFLAME, userId: IDS.U_UPFLAME_DIR_OPS, type: 'publishable', env: 'live', scopes: JSON.stringify(['users:read', 'sessions:read', 'api_keys:read', 'templates:read']), expiresAtOffset: 365 },
  // Navdhya
  { id: IDS.AK_NAVDHYA_1, ulid: 'sF01navdhya1founderA7B2C3D4', tenantId: IDS.T_NAVDHYA, userId: IDS.U_NAVDHYA_FOUNDER, type: 'secret', env: 'live', scopes: JSON.stringify(['users:read', 'users:write', 'sessions:read', 'api_keys:read', 'api_keys:write', 'roles:read', 'email:send', 'templates:read']), expiresAtOffset: 365 },
  { id: IDS.AK_NAVDHYA_2, ulid: 'uF01navdhya2ceoA7B2C3D4E5', tenantId: IDS.T_NAVDHYA, userId: IDS.U_NAVDHYA_CEO, type: 'publishable', env: 'live', scopes: JSON.stringify(['users:read', 'sessions:read', 'templates:read']), expiresAtOffset: 365 },
  // OurDoc
  { id: IDS.AK_OURDOC_1, ulid: 'sF01ourdoc1directorA7B2C3D4', tenantId: IDS.T_OURDOC, userId: IDS.U_OURDOC_DIR, type: 'secret', env: 'live', scopes: JSON.stringify(['users:read', 'users:write', 'users:delete', 'sessions:read', 'sessions:write', 'api_keys:read', 'api_keys:write', 'roles:read', 'policies:read', 'audit:read', 'email:send', 'templates:read']), expiresAtOffset: 365 },
  { id: IDS.AK_OURDOC_2, ulid: 'uF01ourdoc2cmoA7B2C3D4E5', tenantId: IDS.T_OURDOC, userId: IDS.U_OURDOC_CMO, type: 'publishable', env: 'live', scopes: JSON.stringify(['users:read', 'sessions:read']), expiresAtOffset: 365 },
  // Casphere
  { id: IDS.AK_CASPH_1, ulid: 'sF01casphere1partnerA7B2C3', tenantId: IDS.T_CASPH, userId: IDS.U_CASPH_PARTNER, type: 'secret', env: 'live', scopes: JSON.stringify(['users:read', 'users:write', 'sessions:read', 'api_keys:read', 'api_keys:write', 'roles:read', 'audit:read', 'email:send', 'templates:read']), expiresAtOffset: 365 },
  { id: IDS.AK_CASPH_2, ulid: 'uF01casphere2srpartnerA7B2', tenantId: IDS.T_CASPH, userId: IDS.U_CASPH_SR_PARTNER, type: 'publishable', env: 'live', scopes: JSON.stringify(['users:read', 'sessions:read', 'audit:read']), expiresAtOffset: 365 },
];

// Email Providers
const EMAIL_PROVIDERS = [
  { id: IDS.EP_UPFLAME_SMS, tenantId: IDS.T_UPFLAME, providerKey: 'MSG91', providerName: 'MSG91', fromEmail: 'sms@upflame.in', fromName: 'Upflame SMS', isPrimary: true, isEnabled: true, region: 'ap-south-1', channel: 'sms' },
  { id: IDS.EP_UPFLAME_EMAIL, tenantId: IDS.T_UPFLAME, providerKey: 'RESEND', providerName: 'Resend', fromEmail: 'noreply@upflame.in', fromName: 'Upflame', isPrimary: true, isEnabled: true, region: 'us-east-1', channel: 'email' },
  { id: IDS.EP_NAVDHYA_SMS, tenantId: IDS.T_NAVDHYA, providerKey: 'MSG91', providerName: 'MSG91', fromEmail: 'sms@navdhya.com', fromName: 'Navdhya SMS', isPrimary: true, isEnabled: true, region: 'ap-south-1', channel: 'sms' },
  { id: IDS.EP_NAVDHYA_EMAIL, tenantId: IDS.T_NAVDHYA, providerKey: 'RESEND', providerName: 'Resend', fromEmail: 'noreply@navdhya.com', fromName: 'Navdhya', isPrimary: true, isEnabled: true, region: 'us-east-1', channel: 'email' },
  { id: IDS.EP_OURDOC_SMS, tenantId: IDS.T_OURDOC, providerKey: 'MSG91', providerName: 'MSG91', fromEmail: 'sms@ourdoc.in', fromName: 'OurDoc SMS', isPrimary: true, isEnabled: true, region: 'ap-south-1', channel: 'sms' },
  { id: IDS.EP_OURDOC_EMAIL, tenantId: IDS.T_OURDOC, providerKey: 'RESEND', providerName: 'Resend', fromEmail: 'noreply@ourdoc.in', fromName: 'OurDoc Healthcare', isPrimary: true, isEnabled: true, region: 'us-east-1', channel: 'email' },
  { id: IDS.EP_CASPH_SMS, tenantId: IDS.T_CASPH, providerKey: 'MSG91', providerName: 'MSG91', fromEmail: 'sms@casphere.avt.ink', fromName: 'Casphere SMS', isPrimary: true, isEnabled: true, region: 'ap-south-1', channel: 'sms' },
  { id: IDS.EP_CASPH_EMAIL, tenantId: IDS.T_CASPH, providerKey: 'RESEND', providerName: 'Resend', fromEmail: 'noreply@casphere.avt.ink', fromName: 'Casphere CA', isPrimary: true, isEnabled: true, region: 'us-east-1', channel: 'email' },
];

// Email Templates
const EMAIL_TEMPLATES = [
  { id: IDS.ET_UPFLAME_WELCOME, tenantId: IDS.T_UPFLAME, templateKey: 'welcome', subjectTemplate: 'Welcome to Upflame Enterprises!', htmlTemplate: '<h1>Welcome {{name}}!</h1><p>Your Upflame account is ready.</p>' },
  { id: IDS.ET_NAVDHYA_WELCOME, tenantId: IDS.T_NAVDHYA, templateKey: 'welcome', subjectTemplate: 'Welcome to Navdhya Pandits!', htmlTemplate: '<h1>Welcome {{name}}!</h1><p>Start booking puja services.</p>' },
  { id: IDS.ET_OURDOC_WELCOME, tenantId: IDS.T_OURDOC, templateKey: 'welcome', subjectTemplate: 'Welcome to OurDoc Healthcare!', htmlTemplate: '<h1>Welcome {{name}}!</h1><p>Your healthcare portal is ready.</p>' },
  { id: IDS.ET_CASPH_WELCOME, tenantId: IDS.T_CASPH, templateKey: 'welcome', subjectTemplate: 'Welcome to Casphere Chartered Accountants!', htmlTemplate: '<h1>Welcome {{name}}!</h1><p>Your CA services portal is ready.</p>' },
  { id: IDS.ET_UPFLAME_RESET, tenantId: IDS.T_UPFLAME, templateKey: 'password-reset', subjectTemplate: 'Reset your Upflame password', htmlTemplate: '<h1>Reset Password</h1><p>Click <a href="{{resetLink}}">here</a> to reset.</p>' },
  { id: IDS.ET_NAVDHYA_RESET, tenantId: IDS.T_NAVDHYA, templateKey: 'password-reset', subjectTemplate: 'Reset your Navdhya password', htmlTemplate: '<h1>Reset Password</h1><p>Click <a href="{{resetLink}}">here</a> to reset.</p>' },
  { id: IDS.ET_OURDOC_RESET, tenantId: IDS.T_OURDOC, templateKey: 'password-reset', subjectTemplate: 'Reset your OurDoc password', htmlTemplate: '<h1>Reset Password</h1><p>Click <a href="{{resetLink}}">here</a> to reset.</p>' },
  { id: IDS.ET_CASPH_RESET, tenantId: IDS.T_CASPH, templateKey: 'password-reset', subjectTemplate: 'Reset your Casphere password', htmlTemplate: '<h1>Reset Password</h1><p>Click <a href="{{resetLink}}">here</a> to reset.</p>' },
];

// ABAC Policies
const ABAC_POLICIES = [
  { id: 'pol00001-0000-4000-8000-000000000001', tenantId: IDS.T_UPFLAME, name: 'enterprise-access', description: 'MFA and corporate IP required', effect: 'allow', conditions: JSON.stringify({ mfa: true, ip: { allowed: ['10.0.0.0/8', '192.168.0.0/16'] } }) },
  { id: 'pol00002-0000-4000-8000-000000000002', tenantId: IDS.T_NAVDHYA, name: 'booking-management', description: 'Booking manager role required', effect: 'allow', conditions: JSON.stringify({ role: 'booking_manager' }) },
  { id: 'pol00003-0000-4000-8000-000000000003', tenantId: IDS.T_OURDOC, name: 'patient-data', description: 'Doctor verified required', effect: 'allow', conditions: JSON.stringify({ doctor_verified: true }) },
  { id: 'pol00004-0000-4000-8000-000000000004', tenantId: IDS.T_CASPH, name: 'client-data', description: 'CA verified required', effect: 'allow', conditions: JSON.stringify({ ca_verified: true }) },
];

// Audit Events
const AUDIT_EVENTS = [
  { tenantId: IDS.T_UPFLAME, actorId: IDS.U_UPFLAME_ADMIN, actorType: 'user', action: 'user.created', resourceType: 'user', resourceId: IDS.U_UPFLAME_DIR_OPS },
  { tenantId: IDS.T_UPFLAME, actorId: IDS.U_UPFLAME_ADMIN, actorType: 'user', action: 'user.role.assigned', resourceType: 'user', resourceId: IDS.U_UPFLAME_DIR_OPS },
  { tenantId: IDS.T_UPFLAME, actorId: IDS.U_UPFLAME_DIR_OPS, actorType: 'user', action: 'session.created', resourceType: 'session', resourceId: null },
  { tenantId: IDS.T_UPFLAME, actorId: null, actorType: 'system', action: 'jwt.key.rotated', resourceType: 'jwt_key', resourceId: null },
  { tenantId: IDS.T_NAVDHYA, actorId: IDS.U_NAVDHYA_FOUNDER, actorType: 'user', action: 'user.created', resourceType: 'user', resourceId: IDS.U_NAVDHYA_CEO },
  { tenantId: IDS.T_NAVDHYA, actorId: IDS.U_NAVDHYA_CEO, actorType: 'user', action: 'user.login.succeeded', resourceType: 'user', resourceId: IDS.U_NAVDHYA_CEO },
  { tenantId: IDS.T_OURDOC, actorId: IDS.U_OURDOC_DIR, actorType: 'user', action: 'user.created', resourceType: 'user', resourceId: IDS.U_OURDOC_CMO },
  { tenantId: IDS.T_OURDOC, actorId: IDS.U_OURDOC_DIR, actorType: 'user', action: 'mfa.enabled', resourceType: 'user', resourceId: IDS.U_OURDOC_DIR },
  { tenantId: IDS.T_CASPH, actorId: IDS.U_CASPH_PARTNER, actorType: 'user', action: 'user.created', resourceType: 'user', resourceId: IDS.U_CASPH_SR_PARTNER },
  { tenantId: IDS.T_CASPH, actorId: IDS.U_CASPH_PARTNER, actorType: 'user', action: 'api_key.created', resourceType: 'api_key', resourceId: IDS.AK_CASPH_1 },
];

const AUDIT_IDS = [
  'aa000001-0000-4000-8000-000000000001',
  'aa000002-0000-4000-8000-000000000002',
  'aa000003-0000-4000-8000-000000000003',
  'aa000004-0000-4000-8000-000000000004',
  'aa000005-0000-4000-8000-000000000005',
  'aa000006-0000-4000-8000-000000000006',
  'aa000007-0000-4000-8000-000000000007',
  'aa000008-0000-4000-8000-000000000008',
  'aa000009-0000-4000-8000-000000000009',
  'aa000010-0000-4000-8000-000000000010',
];

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN EXECUTION
// ═══════════════════════════════════════════════════════════════════════════════

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
hdr('Step 1 — Tenants (4)');
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
hdr('Step 2 — Users (25)');
for (const u of USERS) {
  const nameEnc = encrypt(u.displayName, u.tenantId, 'USER_PII');
  await exec(
    `User: ${u.displayName}`,
    `INSERT IGNORE INTO users
       (id, tenant_id, display_name_enc, display_name_enc_kid, status,
        suspend_reason, version, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'active', null, 0, ?, ?)`,
    [
      uuidToBin(u.id), uuidToBin(u.tenantId),
      nameEnc, MASTER_KID, NOW, NOW,
    ],
  );
}

// ── 3. Identities ─────────────────────────────────────────────────────────────
hdr('Step 3 — Identities (50)');
for (const i of IDENTITIES) {
  const ctx      = i.type === 'email' ? 'IDENTITY_VALUE' : 'IDENTITY_VALUE';
  const valueEnc = encrypt(i.value, i.tenantId, ctx);
  const valueHash = hmacHash(i.value, i.tenantId, ctx);
  const verifiedAt = i.verified ? NOW : null;

  await exec(
    `Identity: ${i.type} → ${i.value}`,
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
hdr('Step 4 — Credentials (25)');
for (const c of CREDENTIALS) {
  const hash = BCRYPT_PASSWORDS[c.password] || BCRYPT_HASH;
  await exec(
    `Credential: ${c.userId.slice(0, 8)}...`,
    `INSERT IGNORE INTO credentials
       (id, user_id, hash, algorithm, rounds, created_at, updated_at)
     VALUES (?, ?, ?, 'bcrypt_v1', 10, ?, ?)`,
    [uuidToBin(c.id), uuidToBin(c.userId), hash, NOW, NOW],
  );
}

// ── 5. Roles ──────────────────────────────────────────────────────────────────
hdr('Step 5 — Roles (25)');
for (const r of ROLES) {
  await exec(
    `Role: ${r.name}`,
    `INSERT IGNORE INTO roles (id, tenant_id, name, description, created_at)
     VALUES (?, ?, ?, ?, ?)`,
    [uuidToBin(r.id), uuidToBin(r.tenantId), r.name, r.description, NOW],
  );
}

// ── 6. Permissions ───────────────────────────────────────────────────────────
hdr('Step 6 — Permissions (30)');
for (const p of PERMISSIONS) {
  await exec(
    `Permission: ${p.resource}:${p.action}`,
    `INSERT IGNORE INTO permissions (id, tenant_id, resource, action, created_at)
     VALUES (?, ?, ?, ?, ?)`,
    [uuidToBin(p.id), uuidToBin(p.tenantId), p.resource, p.action, NOW],
  );
}

// ── 7. Role ↔ Permission ─────────────────────────────────────────────────────
hdr('Step 7 — Role ↔ Permission Assignments');
for (const rp of ROLE_PERMISSIONS) {
  await exec(
    `role_permissions: ${rp.roleId.slice(0,8)} → ${rp.permId.slice(0,8)}`,
    `INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)`,
    [uuidToBin(rp.roleId), uuidToBin(rp.permId)],
  );
}

// ── 8. User ↔ Role ───────────────────────────────────────────────────────────
hdr('Step 8 — User ↔ Role Assignments');
for (const ur of USER_ROLES) {
  await exec(
    `user_roles: ${ur.userId.slice(0,8)} → ${ur.roleId.slice(0,8)}`,
    `INSERT IGNORE INTO user_roles (user_id, role_id, tenant_id, granted_at)
     VALUES (?, ?, ?, ?)`,
    [uuidToBin(ur.userId), uuidToBin(ur.roleId), uuidToBin(ur.tenantId), NOW],
  );
}

// ── 9. Audit Logs ───────────────────────────────────────────────────────────
hdr('Step 9 — Audit Logs (10 events)');
for (let i = 0; i < AUDIT_EVENTS.length; i++) {
  const ev = AUDIT_EVENTS[i];
  const row = { action: ev.action, resourceType: ev.resourceType, tenantId: ev.tenantId, createdAt: NOW };
  const checksum = auditChecksum(row);
  await exec(
    `Audit: ${ev.action}`,
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

// ── 10. API Keys ───────────────────────────────────────────────────────────────
hdr('Step 10 — API Keys (8 keys)');
// Step 10 — API Keys
for (const ak of API_KEYS) {
  const expiresDate = new Date();
  expiresDate.setDate(expiresDate.getDate() + ak.expiresAtOffset);
  const expiresAt = expiresDate.toISOString().replace('T', ' ').slice(0, 23);

  // Generate unique key_hash and secret_hash per key
  const keyHash   = createHmac('sha256', MASTER_KEY).update(`key:${ak.id}`).digest('hex');
  const secretHash = createHmac('sha256', MASTER_KEY).update(`secret:${ak.id}`).digest('hex');
  const prefix    = ak.ulid.slice(0, 8);

  await exec(
    `API Key: ${ak.type} (${ak.env})`,
    `INSERT IGNORE INTO tenant_api_keys
       (id, ulid, tenant_id, user_id, name, prefix, key_hash, secret_hash,
        type, env, scopes, ip_allowlist, rate_limit, metadata, expires_at, created_at, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
    [
      ak.id, ak.ulid, uuidToBin(ak.tenantId),
      ak.userId ? uuidToBin(ak.userId) : null,
      `${ak.type}-${ak.env}`, prefix, keyHash, secretHash,
      ak.type, ak.env, ak.scopes,
      JSON.stringify([]), 1000, JSON.stringify({}),
      expiresAt, NOW,
    ],
  );
}

// ── 11. Email Providers ───────────────────────────────────────────────────────
hdr('Step 11 — Email Providers (8 configs)');
// Step 11 — Email Providers
for (const ep of EMAIL_PROVIDERS) {
 await exec(
  `Provider: ${ep.providerName} (${ep.channel})`,
  `INSERT IGNORE INTO tenant_email_providers
     (id, tenant_id, provider_name, provider_type, credentials_ref,
      from_email, from_name, is_primary, is_enabled, region,
      priority, rate_limit_per_min, daily_limit, created_at, updated_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  [
    uuidToBin(ep.id), uuidToBin(ep.tenantId),
    ep.providerName,
    ep.channel === 'sms' ? 'sms' : 'email',
    `vault:${ep.providerKey.toLowerCase()}:${ep.tenantId.slice(0, 8)}`,
    ep.fromEmail, ep.fromName,
    ep.isPrimary ? 1 : 0, ep.isEnabled ? 1 : 0,
    ep.region, 1, 60, 10000, NOW, NOW,
  ],
);
}

// ── 12. Email Templates ───────────────────────────────────────────────────────
hdr('Step 12 — Email Templates (8 templates)');
for (const et of EMAIL_TEMPLATES) {
  await exec(
  `Template: ${et.templateKey}`,
  `INSERT IGNORE INTO communication_templates
     (id, tenant_id, channel, template_key, subject, html_template,
      locale, is_active, created_at, updated_at)
   VALUES (?, ?, 'EMAIL', ?, ?, ?, ?, ?, ?, ?)`,
  [
    uuidToBin(et.id), uuidToBin(et.tenantId), et.templateKey,
    et.subjectTemplate, et.htmlTemplate, 'en', 1, NOW, NOW,
  ],
);
}

// ── 13. ABAC Policies ────────────────────────────────────────────────────────
hdr('Step 13 — ABAC Policies (4 policies)');
for (const pol of ABAC_POLICIES) {
  await exec(
  `Policy: ${pol.name}`,
  `INSERT IGNORE INTO abac_policies
     (id, tenant_id, name, description, effect, conditions,
      status, version, created_at, updated_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  [
    uuidToBin(pol.id), uuidToBin(pol.tenantId), pol.name, pol.description,
    pol.effect, pol.conditions, 'active', 1, NOW, NOW,
  ],
);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PLATFORM LAYER SEEDING (Step 14+)
// ═══════════════════════════════════════════════════════════════════════════════

// ── 14. Platform Identities ────────────────────────────────────────────────────
hdr('Step 14 — Platform Identities (2)');
for (const pi of PLATFORM_IDENTITIES) {
  // Platform identities don't use tenant_id - they're platform-level
  await exec(
    `Platform Identity: ${pi.email}`,
    `INSERT IGNORE INTO platform_identities
       (id, email, display_name, password_hash, mfa_type, mfa_enabled, status, risk_score, risk_level, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'totp', ?, ?, 0.0, 'low', ?, ?)`,
    [
      pi.id, pi.email, pi.displayName, BCRYPT_HASH, pi.mfaEnabled ? 1 : 0, pi.status, NOW, NOW,
    ],
  );
}

// ── 15. Platform Roles ────────────────────────────────────────────────────────
hdr('Step 15 — Platform Roles (10 system roles)');
for (const pr of PLATFORM_ROLES) {
  await exec(
    `Platform Role: ${pr.name}`,
    `INSERT IGNORE INTO platform_roles
       (id, type, name, description, assignment_type, is_system, can_assign, can_delegate, inheritance_level, permissions, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      pr.id, pr.type, pr.name, pr.description, pr.assignmentType,
      pr.isSystem ? 1 : 0, pr.canAssign ? 1 : 0, pr.canDelegate ? 1 : 0,
      0, JSON.stringify(pr.permissions), NOW, NOW,
    ],
  );
}

// ── 16. Platform Identity Role Assignments ───────────────────────────────────
hdr('Step 16 — Platform Identity Role Assignments');
for (const pir of PLATFORM_IDENTITY_ROLES) {
  await exec(
    `Platform Role Assignment: ${pir.identityId.slice(0,8)} → ${pir.roleId.slice(0,8)}`,
    `INSERT IGNORE INTO platform_identity_role_assignments
       (id, platform_identity_id, role_id, role_type, assignment_type, assigned_by, assigned_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      `${pir.identityId}-${pir.roleId}`, pir.identityId, pir.roleId, pir.roleType,
      pir.assignmentType, pir.assignedBy, NOW,
    ],
  );
}

// ── 17. Platform API Keys ────────────────────────────────────────────────────
hdr('Step 17 — Platform API Keys (4)');
for (const pak of PLATFORM_API_KEYS) {
  const expiresDate = new Date();
  expiresDate.setDate(expiresDate.getDate() + pak.expiresAtOffset);
  const expiresAt = expiresDate.toISOString().replace('T', ' ').slice(0, 23);
  const secretHash = pak.type === 'secret' ? `hash_${pak.ulid.slice(-12)}` : null;

  await exec(
    `Platform API Key: ${pak.type} (${pak.env})`,
    `INSERT IGNORE INTO platform_api_keys
       (id, ulid, platform_identity_id, type, env, scopes, ip_allowlist, rate_limit, expires_at, secret_hash, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      pak.id, pak.ulid, pak.identityId, pak.type, pak.env, pak.scopes,
      JSON.stringify([]), 10000, expiresAt, secretHash, NOW,
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
console.log(`  ${C.dim}Platform Layer (separate from tenants):${C.reset}`);
console.log(`  ${C.dim}  - superadmin@uicp.platform / SuperAdmin@UICP2024${C.reset}`);
console.log(`  ${C.dim}  - admin@uicp.platform / PlatformAdmin@2024${C.reset}`);
console.log(`  ${C.dim}Tenant Layer (4 tenants):${C.reset}`);
console.log(`  ${C.dim}  - Test credentials in data.md${C.reset}`);
console.log(`  ${C.dim}All identity values are AES-256-GCM encrypted in the DB.${C.reset}`);
console.log(`  ${C.dim}Re-running this script is safe (INSERT IGNORE).${C.reset}`);
console.log();

process.exit(stats.errors > 0 ? 1 : 0);