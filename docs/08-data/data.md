---
title: Seed Data Reference
domain: data
owner: Platform Team
criticality: HIGH
runtime-impact: HIGH
security-impact: HIGH
queue-impact: MEDIUM
provider-impact: MEDIUM
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 03-auth/auth-overview.md
  - 08-data/schema-overview.md
  - 08-data/entity-relationships.md
  - V033__platform_identities.sql
  - V034__platform_services.sql
related-docs:
  - 08-data/schema-overview.md
  - 08-data/entity-relationships.md
  - 08-data/migrations.md
  - 03-auth/login-flow.md
  - 03-auth/session-management.md
related-queues:
  - outbox-events
  - audit-events
related-services:
  - mysql-database
  - redis-cache
---

# Seed Data Reference

## Overview

This document describes the seed data created by `scripts/seed-db.mjs` for development and testing environments. UICP has two distinct layers:

1. **Platform Layer** - Separate from tenants, controls the entire platform
2. **Tenant Layer** - Multi-tenant isolated tenant data

---

## Seed Data Summary

### Platform Layer (Separate from Tenants)

| Entity | Count |
|--------|-------|
| Platform Identities | 2 |
| Platform Roles | 10 (system roles) |
| Platform API Keys | 4 |

### Tenant Layer

| Entity | Count |
|--------|-------|
| Tenants | 4 |
| Users | 25 |
| Identities | 50 (email + phone per user) |
| Credentials | 25 |
| Roles | 25 |
| Permissions | 30 |
| API Keys | 8 (tenant-level) |
| Audit Logs | 10 |
| ABAC Policies | 4 |
| Email Providers | 8 |
| Email Templates | 8 |

---

## Platform Layer (Not Tenant-Scoped)

### Platform Identities

Platform identities are separate from tenant users - they manage the entire platform.

| Email | Display Name | Role | Password |
|-------|--------------|------|----------|
| superadmin@uicp.platform | Platform Super Admin | Platform Owner | `SuperAdmin@UICP2024` |
| admin@uicp.platform | Platform Administrator | Platform Administrator | `PlatformAdmin@2024` |

### Platform Roles (System Roles)

| Role ID | Type | Name | Description |
|---------|------|------|-------------|
| pr00001-... | platform-owner | Platform Owner | Root superadmin - full platform access, cannot be restricted |
| pr00002-... | platform-administrator | Platform Administrator | Full admin access to platform services |
| pr00003-... | identity-administrator | Identity Administrator | Manages platform identities & auth |
| pr00004-... | user-administrator | User Administrator | Manages platform user accounts |
| pr00005-... | security-administrator | Security Administrator | Security policies, threat detection |
| pr00006-... | compliance-administrator | Compliance Administrator | Compliance & audit |
| pr00007-... | network-administrator | Network Administrator | Regions & geo-routing |
| pr00008-... | platform-viewer | Platform Viewer | Read-only access |
| pr00009-... | platform-auditor | Platform Auditor | Audit & compliance reporting |
| pr00010-... | api-manager | API Manager | Manage platform API keys |

### Platform API Keys

| ULID | Type | Env | Identity | Scopes |
|------|------|-----|----------|--------|
| sF01platformSuperAdminKEY1234567890 | secret | live | superadmin@uicp.platform | `*` (all permissions) |
| pB01platformSuperAdminDEV123456789 | publishable | dev | superadmin@uicp.platform | platform:read, tenant:read |
| sF01platformAdminKEY1234567890 | secret | live | admin@uicp.platform | platform:read/write, tenant:read/write, identity:read/write, audit:read |
| uF01platformAdminREAD1234567890 | publishable | live | admin@uicp.platform | platform:read, tenant:read, audit:read |

---

## Tenants (4)

| Tenant | Slug | Plan | Domain | Users | MFA Policy | Session TTL |
|--------|------|------|--------|-------|------------|-------------|
| Upflame Enterprises Pvt Ltd | upflame | enterprise | upflame.in | 8 | required | 86400s |
| Navdhya Pandits Services | navdhya | enterprise | navdhya.com | 6 | optional | 72000s |
| OurDoc Healthcare Solutions | ourdoc | enterprise | ourdoc.in | 6 | required | 43200s |
| Casphere Chartered Accountants | casphere | enterprise | casphere.avt.ink | 5 | required | 36000s |

---

## Users and Credentials

> **Note:** Platform-level super admin is separate (see "Platform Layer" above). The following are **tenant-level** users within each organization.

### Upflame Enterprises (8 users)

| Email | Phone | Display Name | Role | Password |
|-------|-------|--------------|------|----------|
| admin@upflame.in | +919876543210 | Rajesh Kumar | Admin | `Upflame@2024` |
| director.ops@upflame.in | +919876543211 | Priya Sharma | Director Operations | `Director@123` |
| manager.sales@upflame.in | +919876543212 | Amit Patel | Sales Manager | `Sales@2024` |
| accounts@upflame.in | +919876543213 | Sonia Gupta | Accounts Head | `Accounts@123` |
| it.head@upflame.in | +919876543214 | Vikram Singh | IT Head | `ITHead@2024` |
| support@upflame.in | +919876543215 | Anita Desai | Support Lead | `Support@123` |
| logistics@upflame.in | +919876543216 | Raj Mehta | Logistics Manager | `Logistics@24` |
| hr@upflame.in | +919876543217 | Neha Khanna | HR Manager | `HR@2024` |

### Navdhya Pandits (6 users)

| Email | Phone | Display Name | Role | Password |
|-------|-------|--------------|------|----------|
| founder@navdhya.com | +919987654321 | Pandit Raghav | Founder | `Navdhya@Fnd2024` |
| ceo@navdhya.com | +919987654322 | Anjali Reddy | CEO | `CEO@Navdhya24` |
| bookings@navdhya.com | +919987654323 | Deepak Verma | Booking Manager | `Bookings@123` |
| ecommerce@navdhya.com | +919987654324 | Kavita Jain | E-commerce Lead | `Ecom@2024` |
| accounts@navdhya.com | +919987654325 | Suresh Prasad | Accounts Manager | `NavdhyaAcct` |
| support@navdhya.com | +919987654326 | Riya Shah | Customer Support | `Support@Navdhya` |

### OurDoc Healthcare (6 users)

| Email | Phone | Display Name | Role | Password |
|-------|-------|--------------|------|----------|
| director@ourdoc.in | +919123456789 | Dr. Sunita Reddy | Hospital Director | `OurDoc@Dir2024` |
| chief.medical@ourdoc.in | +919123456790 | Dr. Ramesh Babu | Chief Medical Officer | `CMO@OurDoc24` |
| admin.hospital@ourdoc.in | +919123456791 | Lakshmi Narayanan | Hospital Admin | `Hospital@2024` |
| accounts@ourdoc.in | +919123456792 | Arun Kumar | Accounts Manager | `Accts@OurDoc` |
| it.security@ourdoc.in | +919123456793 | Jennifer Maria | IT Security | `Security@2024` |
| reception@ourdoc.in | +919123456794 | Smitha Iyer | Receptionist | `Reception@123` |

### Casphere Chartered Accountants (5 users)

| Email | Phone | Display Name | Role | Password |
|-------|-------|--------------|------|----------|
| partner@casphere.avt.ink | +918987654321 | CA Amit Jha | Managing Partner | `Partner@2024` |
| senior.partner@casphere.avt.ink | +918987654322 | CA Shreya Malhotra | Senior Partner | `SrPartner@24` |
| audit.lead@casphere.avt.ink | +918987654323 | CA Aditya Sharma | Audit Lead | `AuditLead@24` |
| tax.consultant@casphere.avt.ink | +918987654324 | CA Fatima Zahra | Tax Consultant | `Tax@Consul24` |
| accounts@casphere.avt.ink | +918987654325 | Nikhil Garg | Accounts Lead | `CAAccounts@24` |

---

## Identities

Each user has:
- **Email identity** - verified (verified = 1)
- **Phone identity** - verified (verified = 1)

All identities stored with:
- `value_enc`: AES-256-GCM encrypted
- `value_hash`: HMAC-SHA256 for lookup
- `value_enc_kid`: encryption key identifier

---

## Roles (25)

Each tenant has tenant-specific business roles:

| Tenant | Roles |
|--------|-------|
| Upflame | super-admin, director-operations, sales-manager, accounts-head, it-head, support-lead, logistics-manager, hr-manager |
| Navdhya | founder, ceo, booking-manager, ecommerce-lead, accounts-manager, customer-support |
| OurDoc | hospital-director, chief-medical-officer, hospital-admin, accounts-manager, it-security, receptionist |
| Casphere | managing-partner, senior-partner, audit-lead, tax-consultant, accounts-lead |

---

## Permissions (30)

Granular resource:action format:

| Resource | Actions |
|----------|---------|
| users | read, write, delete |
| sessions | read, write |
| audit | read, write |
| iam | manage |
| api_keys | read, write |
| roles | read, write |
| policies | read, write |
| email | send |
| templates | read, write |
| webhooks | write |
| identities | read, write |
| credentials | read, write |
| tenants | read, write |
| providers | read, write |
| extensions | read, write |
| impersonation | start, end |

---

## API Keys (8)

### ULID-Based Dual Key System

| Tenant | ULID | Type | Env | Scopes |
|--------|------|------|-----|--------|
| **Platform (Super Admin)** | sF01platformSuperAdminXYZ12345678 | secret | live | platform:super_admin, tenants:read, tenants:write, users:*, sessions:*, api_keys:*, roles:*, policies:*, audit:*, email:*, templates:*, webhooks:*, identities:*, credentials:*, providers:*, extensions:*, impersonation:* |
| Upflame | uF01upflame2opsA7B2C3D4E5 | publishable | live | users:read,sessions:read,api_keys:read,templates:read |
| Navdhya | sF01navdhya1founderA7B2C3D4 | secret | live | users:read,users:write,sessions:read,api_keys:*,roles:read,email:send,templates:read |
| Navdhya | uF01navdhya2ceoA7B2C3D4E5 | publishable | live | users:read,sessions:read,templates:read |
| OurDoc | sF01ourdoc1directorA7B2C3D4 | secret | live | users:read,users:write,users:delete,sessions:*,api_keys:*,roles:read,policies:read,audit:read,email:send,templates:read |
| OurDoc | uF01ourdoc2cmoA7B2C3D4E5 | publishable | live | users:read,sessions:read |
| Casphere | sF01casphere1partnerA7B2C3 | secret | live | users:read,users:write,sessions:read,api_keys:*,roles:read,audit:read,email:send,templates:read |
| Casphere | uF01casphere2srpartnerA7B2 | publishable | live | users:read,sessions:read,audit:read |

**Key Properties:**
- **Platform Super Admin Key** (`sF01platformSuperAdminXYZ12345678`): Can authenticate into ANY tenant via the platform role
- Prefix: `uF` = Live Publishable, `sF` = Live Secret, `pB` = Dev Publishable, `tB` = Dev Secret
- All PII encrypted with AES-256-GCM
- Secret keys require HMAC validation
- Rate Limit: 1000 req/min

---

## Sessions

Session data stored in Redis:
- Key: `auth-session:{tenantId}:{sessionId}`
- TTL: Per tenant (36000-86400 seconds)
- Includes: user_id, tenant_id, ip_hash, device_fingerprint, created_at

---

## Audit Logs (10 events)

| Tenant | Action | Actor |
|--------|--------|-------|
| Upflame | user.created | admin |
| Upflame | user.role.assigned | admin |
| Upflame | session.created | director.ops |
| Upflame | jwt.key.rotated | system |
| Navdhya | user.created | founder |
| Navdhya | user.login.succeeded | ceo |
| OurDoc | user.created | director |
| OurDoc | mfa.enabled | director |
| Casphere | user.created | partner |
| Casphere | api_key.created | partner |

---

## ABAC Policies (4)

| Tenant | Policy Name | Description | Conditions |
|--------|-------------|-------------|------------|
| Upflame | enterprise-access | MFA and corporate IP required | mfa: true, ip: [10.0.0.0/8, 192.168.0.0/16] |
| Navdhya | booking-management | Booking manager role required | role: booking_manager |
| OurDoc | patient-data | Doctor verified required | doctor_verified: true |
| Casphere | client-data | CA verified required | ca_verified: true |

---

## Email Providers

| Tenant | Channel | Provider | Sender ID | From Email |
|--------|---------|----------|-----------|------------|
| Upflame | SMS | MSG91 | UPFLME | sms@upflame.in |
| Upflame | Email | RESEND | - | noreply@upflame.in |
| Navdhya | SMS | MSG91 | NAVDHYA | sms@navdhya.com |
| Navdhya | Email | RESEND | - | noreply@navdhya.com |
| OurDoc | SMS | MSG91 | OURDOC | sms@ourdoc.in |
| OurDoc | Email | RESEND | - | noreply@ourdoc.in |
| Casphere | SMS | MSG91 | CSPHRC | sms@casphere.avt.ink |
| Casphere | Email | RESEND | - | noreply@casphere.avt.ink |

---

## Email Templates

| Tenant | Template Key | Subject |
|--------|--------------|---------|
| Upflame | welcome | Welcome to Upflame Enterprises! |
| Navdhya | welcome | Welcome to Navdhya Pandits! |
| OurDoc | welcome | Welcome to OurDoc Healthcare! |
| Casphere | welcome | Welcome to Casphere Chartered Accountants! |
| Upflame | password-reset | Reset your Upflame password |
| Navdhya | password-reset | Reset your Navdhya password |
| OurDoc | password-reset | Reset your OurDoc password |
| Casphere | password-reset | Reset your Casphere password |

---

## Data Relationships

```
Tenant
  ├── Users (1:N)
  │     ├── Identities (1:N)
  │     ├── Credentials (1:1)
  │     └── Sessions (1:N - Redis)
  ├── Roles (1:N)
  │     └── RolePermissions (N:N -> Permissions)
  ├── Permissions (1:N)
  ├── ApiKeys (1:N)
  ├── ABACPolicies (1:N)
  ├── TenantEmailProviders (1:N)
  └── EmailTemplates (1:N)
```

---

## Related Documents

- `08-data/schema-overview.md` - Core database schema
- `08-data/entity-relationships.md` - Detailed ER diagrams
- `08-data/migrations.md` - Database migrations
- `03-auth/login-flow.md` - Authentication flows
- `03-auth/session-management.md` - Session handling