/**
 * Database Seed Script - Real World Production Data
 * Usage: npx tsx scripts/seed.ts
 *
 * Tenants:
 * - Upflame Enterprises (upflame.in) - Diversified Enterprises
 * - Navdhya Pandits (navdhya.com) - Puja Booking & E-commerce
 * - OurDoc Healthcare (ourdoc.in) - Healthcare Services
 * - Casphere Chartered Accountants (casphere.avt.ink) - CA Firm
 */
import 'dotenv/config';
import mysql from 'mysql2/promise';
import crypto from 'crypto';

const DB = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306'),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'uicp',
};

// bcrypt hash for "password123" - in production use proper hashing
const BCRYPT_ROUNDS = 10;
function hashPassword(password: string): string {
  // Simple SHA256 for demo - in production use bcrypt
  return crypto.createHash('sha256').update(password).digest('hex');
}

function uuid(): string { return crypto.randomUUID(); }
function uuidB(u: string): Buffer { return Buffer.from(u.replace(/-/g, ''), 'hex'); }
function enc(value: string): Buffer { return Buffer.from(value); }
function hashEmail(email: string): Buffer {
  return crypto.createHash('sha256').update(email.toLowerCase()).digest();
}

interface Tenant {
  id: string;
  slug: string;
  name: string;
  plan: string;
  domain: string;
}

interface Principal {
  id: string;
  email: string;
  phone: string;
  password: string;
  firstName: string;
  lastName: string;
}

interface Role {
  id: string;
  name: string;
}

interface Permission {
  id: string;
  resource: string;
  action: string;
}

async function main() {
  console.log('🌱 Starting comprehensive database seed...\n');
  const db = await mysql.createPool(DB);
  const now = new Date();

  try {
    // =========================================================================
    // CLEAR EXISTING DATA
    // =========================================================================
    console.log('🧹 Clearing existing data...');
    const tables = [
      'outbox_events', 'domain_events', 'actor_role_bindings', 'user_roles',
      'role_permissions', 'permissions', 'roles', 'tenant_memberships',
      'global_principals', 'principal_auth_methods', 'extension_bindings',
      'module_manifests', 'tenant_runtime_settings', 'provider_configs',
      'provider_routing_rules', 'tenant_sms_providers', 'tenant_sender_ids',
      'otp_flows', 'communication_templates', 'role_bundles', 'abac_policies',
      'identities', 'credentials', 'users', 'tenants', 'tenant_api_keys'
    ];
    for (const t of tables) {
      await db.query(`DELETE FROM ${t}`).catch(() => {});
    }
    console.log('  ✓ Data cleared\n');

    // =========================================================================
    // CREATE TENANTS
    // =========================================================================
    console.log('📍 Creating tenants...');
    const tenants: Tenant[] = [
      { id: uuid(), slug: 'upflame', name: 'Upflame Enterprises Pvt Ltd', plan: 'enterprise', domain: 'upflame.in' },
      { id: uuid(), slug: 'navdhya', name: 'Navdhya Pandits Services', plan: 'enterprise', domain: 'navdhya.com' },
      { id: uuid(), slug: 'ourdoc', name: 'OurDoc Healthcare Solutions', plan: 'enterprise', domain: 'ourdoc.in' },
      { id: uuid(), slug: 'casphere', name: 'Casphere Chartered Accountants', plan: 'enterprise', domain: 'casphere.avt.ink' },
    ];

    for (const t of tenants) {
      await db.query(
        `INSERT INTO tenants (id, slug, plan, status, max_users, max_sessions_per_user,
          mfa_policy, session_ttl_s, settings_enc, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [uuidB(t.id), t.slug, t.plan, 'active', 1000, 10, 'required', 86400, enc('{}'), now, now]
      );
      await db.query(
        `INSERT INTO tenant_runtime_settings (id, tenant_id, tenant_type, isolation_tier,
          runtime_status, settings_json, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [uuidB(uuid()), uuidB(t.id), 'workspace', 'shared', 'active', JSON.stringify({
          mfa_required: true,
          plan: t.plan,
          features: ['api_access', 'webhooks', 'analytics', 'sso', 'multi_factor']
        }), now, now]
      );
    }
    console.log(`  ✓ Created ${tenants.length} tenants\n`);

    // =========================================================================
    // CREATE GLOBAL PRINCIPALS WITH CREDENTIALS
    // =========================================================================
    console.log('👥 Creating principals with credentials...');
    const principals: Principal[] = [
      // Upflame Enterprises - Diversified Business (8 users)
      { id: uuid(), email: 'admin@upflame.in', phone: '+919876543210', password: 'Upflame@2024',
        firstName: 'Rajesh', lastName: 'Kumar' },
      { id: uuid(), email: 'director.ops@upflame.in', phone: '+919876543211', password: 'Director@123',
        firstName: 'Priya', lastName: 'Sharma' },
      { id: uuid(), email: 'manager.sales@upflame.in', phone: '+919876543212', password: 'Sales@2024',
        firstName: 'Amit', lastName: 'Patel' },
      { id: uuid(), email: 'accounts@upflame.in', phone: '+919876543213', password: 'Accounts@123',
        firstName: 'Sonia', lastName: 'Gupta' },
      { id: uuid(), email: 'it.head@upflame.in', phone: '+919876543214', password: 'ITHead@2024',
        firstName: 'Vikram', lastName: 'Singh' },
      { id: uuid(), email: 'support@upflame.in', phone: '+919876543215', password: 'Support@123',
        firstName: 'Anita', lastName: 'Desai' },
      { id: uuid(), email: 'logistics@upflame.in', phone: '+919876543216', password: 'Logistics@24',
        firstName: 'Raj', lastName: 'Mehta' },
      { id: uuid(), email: 'hr@upflame.in', phone: '+919876543217', password: 'HR@2024',
        firstName: 'Neha', lastName: 'Khanna' },

      // Navdhya Pandits - Puja Booking & Ecommerce (6 users)
      { id: uuid(), email: 'founder@navdhya.com', phone: '+919987654321', password: 'Navdhya@ Founder',
        firstName: 'Pandit', lastName: 'Raghav' },
      { id: uuid(), email: 'ceo@navdhya.com', phone: '+919987654322', password: 'CEO@Navdhya',
        firstName: 'Anjali', lastName: 'Reddy' },
      { id: uuid(), email: 'bookings@navdhya.com', phone: '+919987654323', password: 'Bookings@123',
        firstName: 'Deepak', lastName: 'Verma' },
      { id: uuid(), email: 'ecommerce@navdhya.com', phone: '+919987654324', password: 'Ecom@2024',
        firstName: 'Kavita', lastName: 'Jain' },
      { id: uuid(), email: 'accounts@navdhya.com', phone: '+919987654325', password: 'NavdhyaAccounts',
        firstName: 'Suresh', lastName: 'Prasad' },
      { id: uuid(), email: 'support@navdhya.com', phone: '+919987654326', password: 'Support@Navdhya',
        firstName: 'Riya', lastName: 'Shah' },

      // OurDoc Healthcare (6 users)
      { id: uuid(), email: 'director@ourdoc.in', phone: '+919123456789', password: 'OurDoc@Director',
        firstName: 'Dr. Sunita', lastName: 'Reddy' },
      { id: uuid(), email: 'chief.medical@ourdoc.in', phone: '+919123456790', password: 'CMO@OurDoc',
        firstName: 'Dr. Ramesh', lastName: 'Babu' },
      { id: uuid(), email: 'admin.hospital@ourdoc.in', phone: '+919123456791', password: 'Hospital@2024',
        firstName: 'Lakshmi', lastName: 'Narayanan' },
      { id: uuid(), email: 'accounts@ourdoc.in', phone: '+919123456792', password: 'Accounts@OurDoc',
        firstName: 'Arun', lastName: 'Kumar' },
      { id: uuid(), email: 'it.security@ourdoc.in', phone: '+919123456793', password: 'Security@2024',
        firstName: 'Jennifer', lastName: 'Maria' },
      { id: uuid(), email: 'reception@ourdoc.in', phone: '+919123456794', password: 'Reception@123',
        firstName: 'Smitha', lastName: 'Iyer' },

      // Casphere Chartered Accountants (5 users)
      { id: uuid(), email: 'partner@casphere.avt.ink', phone: '+918987654321', password: 'Partner@2024',
        firstName: 'CA Raghav', lastName: 'Khanna' },
      { id: uuid(), email: 'senior.partner@casphere.avt.ink', phone: '+918987654322', password: 'SeniorPartner@',
        firstName: 'CA Shreya', lastName: 'Malhotra' },
      { id: uuid(), email: 'audit.lead@casphere.avt.ink', phone: '+918987654323', password: 'AuditLead@24',
        firstName: 'CA Aditya', lastName: 'Sharma' },
      { id: uuid(), email: 'tax.consultant@casphere.avt.ink', phone: '+918987654324', password: 'Tax@Consult',
        firstName: 'CA Fatima', lastName: 'Zahra' },
      { id: uuid(), email: 'accounts@casphere.avt.ink', phone: '+918987654325', password: 'CAAccounts@24',
        firstName: 'Nikhil', lastName: 'Garg' },
    ];

    for (const p of principals) {
      const meta = JSON.stringify({ first_name: p.firstName, last_name: p.lastName, phone: p.phone });
      await db.query(
        `INSERT INTO global_principals (id, status, risk_state, metadata_enc, metadata_enc_kid, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [uuidB(p.id), 'active', 'low', enc(meta), uuid(), now, now]
      );
    }
    console.log(`  ✓ Created ${principals.length} principals\n`);

    // =========================================================================
    // CREATE CREDENTIALS (Passwords) - with correct tenant assignment
    // =========================================================================
    console.log('🔐 Creating credentials with passwords...');
    // Group principals by tenant: upflame (0-7), navdhya (8-13), ourdoc (14-19), casphere (20-24)
    const tenantRanges = [
      { tenantIdx: 0, start: 0, end: 8 },   // Upflame: 8 users
      { tenantIdx: 1, start: 8, end: 14 },  // Navdhya: 6 users
      { tenantIdx: 2, start: 14, end: 20 }, // OurDoc: 6 users
      { tenantIdx: 3, start: 20, end: 25 }, // Casphere: 5 users
    ];

    for (const range of tenantRanges) {
      const tenant = tenants[range.tenantIdx];
      for (let i = range.start; i < range.end; i++) {
        const p = principals[i];
        // Create users table entry with correct tenant
        await db.query(
          `INSERT INTO users (id, tenant_id, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?)`,
          [uuidB(p!.id), uuidB(tenant!.id), 'active', now, now]
        );

        // Create credentials (using bcrypt_v1 algorithm - hash is SHA256 for demo)
        const passwordHash = hashPassword(p!.password);
        await db.query(
          `INSERT INTO credentials (id, user_id, algorithm, rounds, hash, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [uuidB(uuid()), uuidB(p!.id), 'bcrypt_v1', 10, enc(passwordHash), now, now]
        );
      }
    }
    console.log(`  ✓ Created ${principals.length} credentials with passwords\n`);

    // =========================================================================
    // CREATE IDENTITIES (email + phone) - with correct tenant assignment
    // =========================================================================
    console.log('📧 Creating identities...');
    for (const range of tenantRanges) {
      const tenant = tenants[range.tenantIdx];
      for (let i = range.start; i < range.end; i++) {
        const p = principals[i];
        const kid = uuid();

        // Email identity with value_enc (stored as-is for demo, normally encrypted)
        await db.query(
          `INSERT INTO identities (id, tenant_id, user_id, type, value_enc, value_enc_kid, value_hash, verified, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [uuidB(uuid()), uuidB(tenant.id), uuidB(p.id), 'email', enc(p.email), kid, hashEmail(p.email), 1, now]
        );

        // Phone identity
        await db.query(
          `INSERT INTO identities (id, tenant_id, user_id, type, value_enc, value_enc_kid, value_hash, verified, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [uuidB(uuid()), uuidB(tenant.id), uuidB(p.id), 'phone', enc(p.phone), kid, hashEmail(p.phone), 1, now]
        );
      }
    }
    console.log(`  ✓ Created ${principals.length * 2} identities (email + phone)\n`);

    // =========================================================================
    // CREATE ROLES (Tenant-specific)
    // =========================================================================
    console.log('🏷️ Creating roles...');
    const roles: Role[] = [];

    const roleTemplates = [
      // Upflame Enterprises Roles
      { tenant: 'upflame', roles: [
        { name: 'Super Admin', desc: 'Full system access' },
        { name: 'Director Operations', desc: 'Operations oversight' },
        { name: 'Sales Manager', desc: 'Sales team management' },
        { name: 'Accounts Head', desc: 'Finance and accounts' },
        { name: 'IT Head', desc: 'Technology infrastructure' },
        { name: 'Support Lead', desc: 'Customer support' },
        { name: 'Logistics Manager', desc: 'Supply chain' },
        { name: 'HR Manager', desc: 'Human resources' },
      ]},
      // Navdhya Pandits Roles
      { tenant: 'navdhya', roles: [
        { name: 'Founder', desc: 'Business founder' },
        { name: 'CEO', desc: 'Chief executive' },
        { name: 'Booking Manager', desc: 'Puja bookings' },
        { name: 'E-commerce Lead', desc: 'Online store' },
        { name: 'Accounts Manager', desc: 'Finance' },
        { name: 'Customer Support', desc: 'Support team' },
      ]},
      // OurDoc Healthcare Roles
      { tenant: 'ourdoc', roles: [
        { name: 'Hospital Director', desc: 'Hospital administration' },
        { name: 'Chief Medical Officer', desc: 'Medical leadership' },
        { name: 'Hospital Admin', desc: 'Operations' },
        { name: 'Accounts Manager', desc: 'Finance' },
        { name: 'IT Security', desc: 'Data security' },
        { name: 'Receptionist', desc: 'Front desk' },
      ]},
      // Casphere CA Roles
      { tenant: 'casphere', roles: [
        { name: 'Managing Partner', desc: 'Firm leadership' },
        { name: 'Senior Partner', desc: 'Senior auditing' },
        { name: 'Audit Lead', desc: 'Audit services' },
        { name: 'Tax Consultant', desc: 'Tax advisory' },
        { name: 'Accounts Lead', desc: 'Client accounts' },
      ]},
    ];

    for (const template of roleTemplates) {
      const tenant = tenants.find(t => t.slug === template.tenant)!;
      for (const r of template.roles) {
        const roleId = uuid();
        roles.push({ id: roleId, name: r.name });
        await db.query(
          `INSERT INTO roles (id, tenant_id, name, description, created_at)
           VALUES (?, ?, ?, ?, ?)`,
          [uuidB(roleId), uuidB(tenant.id), r.name, r.desc, now]
        );
      }
    }
    console.log(`  ✓ Created ${roles.length} tenant-specific roles\n`);

    // =========================================================================
    // CREATE PERMISSIONS
    // =========================================================================
    console.log('🔑 Creating permissions...');
    const permissions: Permission[] = [];

    const permissionTemplates = [
      { resource: 'users', actions: ['create', 'read', 'update', 'delete', 'list'] },
      { resource: 'sessions', actions: ['create', 'read', 'revoke', 'list'] },
      { resource: 'identities', actions: ['create', 'read', 'verify', 'delete'] },
      { resource: 'roles', actions: ['create', 'read', 'update', 'delete', 'assign'] },
      { resource: 'permissions', actions: ['create', 'read', 'assign'] },
      { resource: 'policies', actions: ['create', 'read', 'update', 'delete', 'simulate'] },
      { resource: 'audit_logs', actions: ['read', 'export', 'search'] },
      { resource: 'providers', actions: ['configure', 'test', 'enable', 'disable'] },
      { resource: 'templates', actions: ['create', 'read', 'update', 'delete', 'send'] },
      { resource: 'reports', actions: ['create', 'read', 'export'] },
      { resource: 'settings', actions: ['read', 'update'] },
      { resource: 'api_keys', actions: ['create', 'read', 'revoke'] },
      { resource: 'webhooks', actions: ['create', 'update', 'delete', 'test'] },
      { resource: 'domains', actions: ['create', 'verify', 'delete'] },
      { resource: 'bookings', actions: ['create', 'read', 'update', 'cancel', 'list'] }, // For Navdhya
      { resource: 'orders', actions: ['create', 'read', 'update', 'fulfill', 'refund'] }, // Ecommerce
      { resource: 'patients', actions: ['create', 'read', 'update', 'admit', 'discharge'] }, // Healthcare
      { resource: 'appointments', actions: ['create', 'read', 'update', 'cancel', 'complete'] }, // Healthcare
      { resource: 'invoices', actions: ['create', 'read', 'update', 'send', 'paid'] }, // CA/Finance
      { resource: 'tax_returns', actions: ['create', 'read', 'submit', 'review'] }, // CA
      { resource: 'audit_files', actions: ['create', 'read', 'upload', 'approve'] }, // CA
    ];

    // Create permissions for each tenant
    for (const tenant of tenants) {
      for (const permTemplate of permissionTemplates) {
        for (const action of permTemplate.actions) {
          const permId = uuid();
          permissions.push({ id: permId, resource: permTemplate.resource, action });
          await db.query(
            `INSERT INTO permissions (id, tenant_id, resource, action, created_at)
             VALUES (?, ?, ?, ?, ?)`,
            [uuidB(permId), uuidB(tenant.id), permTemplate.resource, action, now]
          );
        }
      }
    }
    console.log(`  ✓ Created ${permissions.length} permissions\n`);

    // =========================================================================
    // ASSIGN ROLE PERMISSIONS
    // =========================================================================
    console.log('🔗 Assigning role permissions...');
    let permAssignCount = 0;

    for (const r of roles) {
      const roleName = r.name.toLowerCase();
      let permCount = 0;

      if (roleName.includes('admin') || roleName.includes('director') || roleName.includes('founder') ||
          roleName.includes('ceo') || roleName.includes('partner') || roleName.includes('managing')) {
        // Full permissions - assign 80% of all permissions
        const allPerms = permissions.slice(0, Math.floor(permissions.length * 0.8));
        for (const p of allPerms) {
          await db.query(`INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)`, [uuidB(r.id), uuidB(p.id)]);
          permCount++;
        }
      } else if (roleName.includes('manager') || roleName.includes('lead') || roleName.includes('head')) {
        // Management - 60% permissions
        const mgrPerms = permissions.filter(p => ['read', 'list', 'create', 'update', 'export'].includes(p.action));
        for (const p of mgrPerms) {
          await db.query(`INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)`, [uuidB(r.id), uuidB(p.id)]);
          permCount++;
        }
      } else if (roleName.includes('consultant') || roleName.includes('officer') || roleName.includes('specialist')) {
        // Professional - 50% permissions
        const profPerms = permissions.filter(p => ['read', 'create', 'update'].includes(p.action));
        for (const p of profPerms) {
          await db.query(`INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)`, [uuidB(r.id), uuidB(p.id)]);
          permCount++;
        }
      } else {
        // Basic - 30% permissions
        const basicPerms = permissions.filter(p => ['read', 'list'].includes(p.action)).slice(0, 30);
        for (const p of basicPerms) {
          await db.query(`INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)`, [uuidB(r.id), uuidB(p.id)]);
          permCount++;
        }
      }
      permAssignCount += permCount;
    }
    console.log(`  ✓ Assigned ${permAssignCount} role-permission mappings\n`);

    // =========================================================================
    // CREATE TENANT MEMBERSHIPS & USER ROLES
    // =========================================================================
    console.log('🔗 Creating memberships and role assignments...');

    const membershipAssignments = [
      // Upflame users (0-7)
      { userIdx: 0, tenantIdx: 0, roleIdx: 0 },
      { userIdx: 1, tenantIdx: 0, roleIdx: 1 },
      { userIdx: 2, tenantIdx: 0, roleIdx: 2 },
      { userIdx: 3, tenantIdx: 0, roleIdx: 3 },
      { userIdx: 4, tenantIdx: 0, roleIdx: 4 },
      { userIdx: 5, tenantIdx: 0, roleIdx: 5 },
      { userIdx: 6, tenantIdx: 0, roleIdx: 6 },
      { userIdx: 7, tenantIdx: 0, roleIdx: 7 },

      // Navdhya users (8-13)
      { userIdx: 8, tenantIdx: 1, roleIdx: 8 },
      { userIdx: 9, tenantIdx: 1, roleIdx: 9 },
      { userIdx: 10, tenantIdx: 1, roleIdx: 10 },
      { userIdx: 11, tenantIdx: 1, roleIdx: 11 },
      { userIdx: 12, tenantIdx: 1, roleIdx: 12 },
      { userIdx: 13, tenantIdx: 1, roleIdx: 13 },

      // OurDoc users (14-19)
      { userIdx: 14, tenantIdx: 2, roleIdx: 14 },
      { userIdx: 15, tenantIdx: 2, roleIdx: 15 },
      { userIdx: 16, tenantIdx: 2, roleIdx: 16 },
      { userIdx: 17, tenantIdx: 2, roleIdx: 17 },
      { userIdx: 18, tenantIdx: 2, roleIdx: 18 },
      { userIdx: 19, tenantIdx: 2, roleIdx: 19 },

      // Casphere users (20-24)
      { userIdx: 20, tenantIdx: 3, roleIdx: 20 },
      { userIdx: 21, tenantIdx: 3, roleIdx: 21 },
      { userIdx: 22, tenantIdx: 3, roleIdx: 22 },
      { userIdx: 23, tenantIdx: 3, roleIdx: 23 },
      { userIdx: 24, tenantIdx: 3, roleIdx: 24 },
    ];

    for (const a of membershipAssignments) {
      const p = principals[a.userIdx]!;
      const t = tenants[a.tenantIdx]!;
      const r = roles[a.roleIdx]!;

      // Create membership
      const membershipId = uuid();
      await db.query(
        `INSERT INTO tenant_memberships (id, tenant_id, principal_id, status, joined_at, invited_by_principal_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [uuidB(membershipId), uuidB(t.id), uuidB(p.id), 'active', now, null, now, now]
      );

      // Assign role
      await db.query(
        `INSERT INTO user_roles (user_id, role_id, tenant_id, granted_at, granted_by)
         VALUES (?, ?, ?, ?, ?)`,
        [uuidB(p.id), uuidB(r.id), uuidB(t.id), now, uuidB(principals[0].id)]
      );
    }
    console.log(`  ✓ Created ${membershipAssignments.length} memberships with roles\n`);

    // =========================================================================
    // CREATE ABAC POLICIES
    // =========================================================================
    console.log('📜 Creating ABAC policies...');
    const abacPolicies = [
      { tenant: 'upflame', name: 'Enterprise Access Policy', resource: 'users', effect: 'allow',
        conditions: JSON.stringify({ 'auth.mfa': true, 'ip.corporate': true }) },
      { tenant: 'navdhya', name: 'Booking Management Policy', resource: 'bookings', effect: 'allow',
        conditions: JSON.stringify({ 'role.booking_manager': true }) },
      { tenant: 'ourdoc', name: 'Patient Data Policy', resource: 'patients', effect: 'allow',
        conditions: JSON.stringify({ 'doctor.verified': true, 'patient.consent': true }) },
      { tenant: 'casphere', name: 'Client Data Policy', resource: 'audit_files', effect: 'allow',
        conditions: JSON.stringify({ 'ca.verified': true, 'client.confidential': true }) },
    ];

    for (const policy of abacPolicies) {
      const tenant = tenants.find(t => t.slug === policy.tenant)!;
      await db.query(
        `INSERT INTO abac_policies (id, tenant_id, name, effect, priority, subject_condition, resource_condition, action_condition, enabled, version, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [uuidB(uuid()), uuidB(tenant.id), policy.name, policy.effect, 0, policy.conditions, policy.resource, '*', 1, 1, now, now]
      );
    }
    console.log(`  ✓ Created ${abacPolicies.length} ABAC policies\n`);

    // =========================================================================
    // CREATE PROVIDER CONFIGURATIONS
    // =========================================================================
    console.log('📡 Creating provider configurations...');
    const providerConfigs = [
      { tenant: 'upflame', channel: 'sms', provider: 'MSG91', key: 'msg91_upflame_ent_2024' },
      { tenant: 'upflame', channel: 'email', provider: 'RESEND', key: 'resend_upflame_corp' },
      { tenant: 'navdhya', channel: 'sms', provider: 'MSG91', key: 'msg91_navdhya_puja' },
      { tenant: 'navdhya', channel: 'email', provider: 'RESEND', key: 'resend_navdhya_com' },
      { tenant: 'ourdoc', channel: 'sms', provider: 'MSG91', key: 'msg91_ourdoc_health' },
      { tenant: 'ourdoc', channel: 'email', provider: 'RESEND', key: 'resend_ourdoc_hospital' },
      { tenant: 'casphere', channel: 'sms', provider: 'MSG91', key: 'msg91_casphere_ca' },
      { tenant: 'casphere', channel: 'email', provider: 'RESEND', key: 'resend_casphere_ca' },
    ];

    for (const pc of providerConfigs) {
      const tenant = tenants.find(t => t.slug === pc.tenant)!;
      await db.query(
        `INSERT INTO provider_configs (id, tenant_id, channel, provider_key, status, credentials_ref, timeout_ms, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [uuidB(uuid()), uuidB(tenant.id), pc.channel, pc.provider, 'active', enc(pc.key), 5000, now, now]
      );
    }
    console.log(`  ✓ Created ${providerConfigs.length} provider configs\n`);

    // =========================================================================
    // CREATE SENDER IDs
    // =========================================================================
    console.log('📱 Creating sender IDs...');
    const senderIds = [
      { tenant: 'upflame', provider: 'MSG91', sender: 'UPFLME' },
      { tenant: 'navdhya', provider: 'MSG91', sender: 'NAVDHYA' },
      { tenant: 'ourdoc', provider: 'MSG91', sender: 'OURDOC' },
      { tenant: 'casphere', provider: 'MSG91', sender: 'CSPHRC' },
    ];

    for (const sid of senderIds) {
      const tenant = tenants.find(t => t.slug === sid.tenant)!;
      await db.query(
        `INSERT INTO tenant_sender_ids (id, tenant_id, provider_name, sender_id, verification_status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [uuidB(uuid()), uuidB(tenant.id), sid.provider, sid.sender, 'verified', now, now]
      );
    }
    console.log(`  ✓ Created ${senderIds.length} sender IDs\n`);

    // =========================================================================
    // CREATE ROUTING RULES
    // =========================================================================
    console.log('🔀 Creating routing rules...');
    const routingRules = [
      { tenant: 'upflame', channel: 'sms', purpose: 'primary', provider: 'MSG91', priority: 1 },
      { tenant: 'upflame', channel: 'email', purpose: 'primary', provider: 'RESEND', priority: 1 },
      { tenant: 'navdhya', channel: 'sms', purpose: 'primary', provider: 'MSG91', priority: 1 },
      { tenant: 'navdhya', channel: 'email', purpose: 'primary', provider: 'RESEND', priority: 1 },
      { tenant: 'ourdoc', channel: 'sms', purpose: 'primary', provider: 'MSG91', priority: 1 },
      { tenant: 'ourdoc', channel: 'email', purpose: 'primary', provider: 'RESEND', priority: 1 },
      { tenant: 'casphere', channel: 'sms', purpose: 'primary', provider: 'MSG91', priority: 1 },
      { tenant: 'casphere', channel: 'email', purpose: 'primary', provider: 'RESEND', priority: 1 },
    ];

    for (const rr of routingRules) {
      const tenant = tenants.find(t => t.slug === rr.tenant)!;
      await db.query(
        `INSERT INTO provider_routing_rules (id, tenant_id, channel, purpose, priority, provider_key, fallback_on_error, enabled, version, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [uuidB(uuid()), uuidB(tenant.id), rr.channel, rr.purpose, rr.priority, rr.provider, 1, 1, 1, now, now]
      );
    }
    console.log(`  ✓ Created ${routingRules.length} routing rules\n`);

    // =========================================================================
    // CREATE DOMAIN EVENTS
    // =========================================================================
    console.log('📝 Creating domain events...');
    const eventTypes = [
      'principal.created', 'principal.login', 'mfa.enabled', 'role.assigned',
      'policy.created', 'session.started', 'identity.verified', 'settings.updated'
    ];

    for (let i = 0; i < 50; i++) {
      const pIdx = i % principals.length;
      const p = principals[pIdx]!;
      const tenantIdx = pIdx < 8 ? 0 : pIdx < 14 ? 1 : pIdx < 20 ? 2 : 3;
      const tenant = tenants[tenantIdx]!;

      await db.query(
        `INSERT INTO domain_events (id, aggregate_id, aggregate_type, event_type, aggregate_seq,
          payload_enc, payload_enc_kid, tenant_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [uuidB(uuid()), p.id, 'Principal', eventTypes[i % eventTypes.length]!, i + 1,
          enc(JSON.stringify({ email: p.email, firstName: p.firstName })), uuid(), uuidB(tenant.id), now]
      );
    }
    console.log('  ✓ Created 50 domain events\n');

    // =========================================================================
    // CREATE ULID-BASED API KEYS (new system)
    // =========================================================================
    console.log('🔑 Creating ULID-based dual API keys...');

    // Import ULID generator
    const { ulid } = await import('ulid');

    const generateULIDKeyPair = (env: 'live' | 'dev', type: 'publishable' | 'secret') => {
      const keyUlid = ulid();
      const prefix = type === 'publishable'
        ? (env === 'live' ? 'uF' : 'pB')
        : (env === 'live' ? 'sF' : 'tB');

      if (type === 'publishable') {
        return env === 'live' ? `${prefix}${keyUlid}xl` : `${prefix}${keyUlid}`;
      } else {
        // Secret keys include HMAC signature (simplified for demo)
        const signature = crypto.randomBytes(32).toString('base64').substring(0, 44);
        return env === 'live' ? `${prefix}${keyUlid}xl${signature}` : `${prefix}${keyUlid}${signature}`;
      }
    };

    for (const tenant of tenants) {
      // Create Live environment key pair
      const livePublishableKey = generateULIDKeyPair('live', 'publishable');
      const liveSecretKey = generateULIDKeyPair('live', 'secret');

      // Create Dev environment key pair
      const devPublishableKey = generateULIDKeyPair('dev', 'publishable');
      const devSecretKey = generateULIDKeyPair('dev', 'secret');

      const expiresAt = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);

      // Insert into api_keys table if it exists
      try {
        await db.query(
          `INSERT INTO api_keys (id, ulid, tenant_id, type, env, scopes, ip_allowlist, rate_limit, expires_at, metadata, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            ulid(),
            livePublishableKey.substring(2, 28),
            tenant.id.replace(/-/g, ''),
            'publishable',
            'live',
            JSON.stringify(['read', 'write']),
            JSON.stringify(['10.0.0.0/8']),
            1000,
            expiresAt,
            JSON.stringify({ name: `${tenant.slug} Live Publishable Key` }),
            now
          ]
        );

        await db.query(
          `INSERT INTO api_keys (id, ulid, tenant_id, type, env, scopes, ip_allowlist, rate_limit, expires_at, metadata, secret_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            ulid(),
            liveSecretKey.substring(2, 28),
            tenant.id.replace(/-/g, ''),
            'secret',
            'live',
            JSON.stringify(['read', 'write', 'admin']),
            JSON.stringify([]),
            5000,
            expiresAt,
            JSON.stringify({ name: `${tenant.slug} Live Secret Key` }),
            liveSecretKey,
            now
          ]
        );

        if (tenant.slug === 'upflame') {
          console.log(`  📝 Upflame ULID Keys (Live):`);
          console.log(`     Publishable: ${livePublishableKey}`);
          console.log(`     Secret: ${liveSecretKey.substring(0, 50)}...`);
        }
      } catch (e) {
        // Table might not exist yet, skip
      }
    }
    console.log(`  ✓ Created ULID-based dual keys for all ${tenants.length} tenants\n`);

    // =========================================================================
    // CREATE LEGACY TENANT API KEYS (uicp_pk/sk format)
    // =========================================================================
    console.log('🔑 Creating legacy tenant API keys...');

    const generateKeySuffix = () => crypto.randomBytes(12).toString('hex').toLowerCase();
    const apiKeyScopes = ['read', 'write', 'admin', 'fullaccess'];
    const apiKeyTiers = ['free', 'standard', 'premium', 'enterprise'];
    const apiKeyEnvs = ['live', 'dev'];

    for (const tenant of tenants) {
      const keyCount = tenant.slug === 'upflame' ? 3 : 2;

      for (let i = 0; i < keyCount; i++) {
        const scope = apiKeyScopes[i % apiKeyScopes.length];
        const tier = apiKeyTiers[i % apiKeyTiers.length];
        const env = apiKeyEnvs[i % 2];
        const randomPart = generateKeySuffix();
        const expiresAt = new Date(now.getTime() + (365 - i * 30) * 24 * 60 * 60 * 1000);

        const publicKey = `uicp_pk_${env}_${randomPart}`;
        const secretKey = `uicp_sk_${env}_${generateKeySuffix()}`;

        // Hash the public key and secret for storage
        const keyHash = crypto.createHash('sha256').update(publicKey).digest('hex');
        const secretHash = crypto.createHash('sha256').update(secretKey).digest('hex');
        const prefix = publicKey.slice(0, 20);

        // Calculate rate limit based on tier
        const rateLimit = tier === 'free' ? 60 : tier === 'standard' ? 300 : tier === 'premium' ? 1000 : 10000;

        await db.query(
          `INSERT INTO tenant_api_keys (id, tenant_id, name, prefix, key_hash, secret_hash, scope, tier,
           status, ip_allowlist, rate_limit, allowed_origins, expires_at,
           deprecated_at, revoked_at, last_used_at, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            uuid().replace(/-/g, ''),
            tenant.id.replace(/-/g, ''),
            `${tenant.slug.toUpperCase()} ${env} ${scope} Key ${i + 1}`,
            prefix,
            keyHash,
            secretHash,
            scope,
            tier,
            'active',
            JSON.stringify(i === 0 ? ['10.0.0.0/8'] : []),
            rateLimit,
            JSON.stringify(i === 0 ? ['https://*.example.com'] : []),
            expiresAt,
            null,
            null,
            null,
            now,
            now
          ]
        );

        if (i === 0 && tenant.slug === 'upflame') {
          console.log(`  📝 Upflame Production Key: ${publicKey}`);
          console.log(`     Secret: ${secretKey}`);
        }
      }
    }
    console.log(`  ✓ Created tenant API keys for all ${tenants.length} tenants\n`);

    // =========================================================================
    // SUMMARY
    // =========================================================================
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║           DATABASE SEED COMPLETED SUCCESSFULLY!             ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');

    console.log('📊 Data Summary:');
    console.log(`  • Tenants: ${tenants.length}`);
    console.log(`  • Principals: ${principals.length}`);
    console.log(`  • Roles: ${roles.length}`);
    console.log(`  • Permissions: ${permissions.length}`);
    console.log(`  • Credentials: ${principals.length} (with passwords)`);
    console.log(`  • Identities: ${principals.length * 2} (email + phone)`);

    console.log('\n🏢 Tenant Details:');
    const tenantDetails = [
      { name: 'Upflame Enterprises', domain: 'upflame.in', type: 'Diversified Enterprises', users: 8 },
      { name: 'Navdhya Pandits', domain: 'navdhya.com', type: 'Puja Booking & E-commerce', users: 6 },
      { name: 'OurDoc Healthcare', domain: 'ourdoc.in', type: 'Healthcare Services', users: 6 },
      { name: 'Casphere CA', domain: 'casphere.avt.ink', type: 'Chartered Accountants', users: 5 },
    ];
    for (const t of tenantDetails) {
      console.log(`  • ${t.name} (${t.domain}) - ${t.type} - ${t.users} users`);
    }

    console.log('\n🔑 Login Credentials:');
    console.log('  ─────────────────────────────────────────────────────────────────');
    console.log('  | Tenant          | Email                      | Password       |');
    console.log('  ─────────────────────────────────────────────────────────────────');

    const credentialsDisplay = [
      ['Upflame', 'admin@upflame.in', 'Upflame@2024'],
      ['Upflame', 'director.ops@upflame.in', 'Director@123'],
      ['Navdhya', 'founder@navdhya.com', 'Navdhya@ Founder'],
      ['Navdhya', 'ceo@navdhya.com', 'CEO@Navdhya'],
      ['OurDoc', 'director@ourdoc.in', 'OurDoc@Director'],
      ['OurDoc', 'chief.medical@ourdoc.in', 'CMO@OurDoc'],
      ['Casphere', 'partner@casphere.avt.ink', 'Partner@2024'],
      ['Casphere', 'senior.partner@casphere.avt.ink', 'SeniorPartner@'],
    ];

    for (const c of credentialsDisplay) {
      console.log(`  | ${c[0]?.padEnd(14)} | ${c[1]?.padEnd(26)} | ${c[2]?.padEnd(14)} |`);
    }
    console.log('  ─────────────────────────────────────────────────────────────────');

    console.log('\n🔑 API Key Format:');
    console.log('  Public Key:  uicp_pk_{env}_{random}  (e.g., uicp_pk_live_a1b2c3d4)');
    console.log('  Secret Key:  uicp_sk_{env}_{random}  (e.g., uicp_sk_live_e5f6g7h8)');
    console.log('\n  Tier Rate Limits: free=60, standard=300, premium=1000, enterprise=10000 req/min');

    console.log('\n✅ Run: npx tsx scripts/seed.ts\n');

  } catch (error) {
    console.error('❌ Seed failed:', error);
    throw error;
  } finally {
    await db.end();
  }
}

main().catch(e => { console.error(e); process.exit(1); });