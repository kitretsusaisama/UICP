# UICP API Documentation

> **AI-Native Documentation** - This documentation is structured for AI ingestion, RAG retrieval, and machine-readable context. See [13-ai-context](./13-ai-context/system-summary.md) for AI-optimized summaries.

## Metadata

```yaml
title: UICP API Documentation
domain: api
owner: API Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-15
version: 1.0.0
```

## Architecture Context

### System Type
- **Pattern**: Hexagonal Architecture (Ports & Adapters)
- **Pattern**: CQRS (Command Query Responsibility Segregation)
- **Runtime**: NestJS (Node.js/TypeScript)
- **Database**: MySQL 8.0+ (event store, lineage)
- **Cache**: Redis 6.0+ (sessions, rate limits)
- **Queue**: BullMQ (async processing)

### Trust Model
- **Zero-Trust**: Every request validated
- **Tenant Isolation**: API-key-centric resolution
- **Replay Protection**: Idempotency keys required

### Auth Priority
1. API Key `tenantId` → 2. JWT `tid` claim → 3. Session `tenantId`

---

## Overview

UICP (Universal Identity & Communication Platform) is a domain-aware, API-key-centric multi-tenant identity and communication platform.

**Key Architecture:** Tenant context derived from credentials (API Key, JWT, Session) — no explicit `X-Tenant-ID` header required for authenticated endpoints.

---

## Table of Contents

- [Authentication](#authentication)
- [Unified Auth](#unified-auth-v1auth)
- [Core Auth](#core-auth-v1auth)
- [Password Auth](#password-auth-v1authpassword)
- [OTP Auth](#otp-auth-v1authotp)
- [OAuth](#oauth-v1authoauth)
- [Users](#users-v1users)
- [Sessions](#sessions-v1usersme)
- [API Keys](#api-keys-v1api-keys)
- [Tenant API Keys](#tenant-api-keys-v1tenantapi-keys)
- [Policies](#policies-v1policies)
- [Roles](#roles-v1roles)
- [Dynamic Modules](#dynamic-modules-v1modules)
- [Extensions](#extensions-v1extensions)
- [Communication](#communication-v1)
- [Platform - Tenants](#platform---tenants-platformv1tenants)
- [Platform - Impersonation](#platform---impersonation-platformv1impersonate)
- [Platform - Security](#platform---security-platformv1security)
- [Platform - Audit](#platform---audit-platformv1)
- [Platform - Governance](#platform---governance-platformv1)
- [Platform - Regions](#platform---regions-platformv1regions)
- [Platform - Resilience](#platform---resilience-platformv1resilience)
- [Platform - Approvals](#platform---approvals-platformv1approvals)
- [Platform - Data Governance](#platform---data-governance-platformv1)
- [Platform - Config](#platform---config-platformv1)
- [Platform - DID/VC](#platform---didvc-platformv1identities)
- [Platform - CA Policies](#platform---ca-policies-platformv1ca-policies)
- [Platform - ZT Policies](#platform---zt-policies-platformv1)
- [Platform - Apps](#platform---apps-v1platformapps)
- [Platform - Apps Secrets](#platform---apps-secrets-v1platformappsappidsecrets)
- [Platform - Domains](#platform---domains-v1platformdomains)
- [Platform - OAuth](#platform---oauth-v1platformoauth)
- [Platform - Webhooks](#platform---webhooks-v1platformwebhooks)
- [Discovery](#discovery-well-known)
- [Admin](#admin-v1admin)
- [Health](#health)

---

## Authentication

### Authorization Header Format

All authenticated endpoints accept the following Authorization header formats:

```
Authorization: Bearer <token>
```

**Token Types:**
- **API Key** (ULID-based, uF/pB/sF/tB prefix) — Production/Dev publishable or secret keys
- **JWT** — Access/Refresh tokens with `tid` claim for tenant context
- **Session Token** — X-Session-Token header alternative

### Auth Priority

Tenant context resolution priority (tenant derived from credential, not header):
1. API Key `tenantId` → 2. JWT `tid` claim → 3. Session `tenantId` → 4. No fallback (API-key-centric)

---

## Unified Auth (`/v1/auth`)

UICP provides multiple authentication methods for flexible identity verification.

### Authentication Method Types

#### Unified Auth Attempt Methods (`/v1/auth/attempt`)

| Method | Value | Description | Secret Required |
|--------|-------|-------------|------------------|
| Password | `password` | Email/phone + password authentication | Yes |
| OTP | `otp` | One-time password (SMS/Email) | Yes (code) |
| Magic Link | `magic_link` | Email-based magic link | No |
| OAuth | `oauth` | External OAuth provider (Google, GitHub, etc.) | No |

#### Credential-Based Authentication (Bearer Token)

| Method | Header | Format | Use Case |
|--------|--------|--------|----------|
| JWT | `Authorization: Bearer <token>` | RS256 signed access token | User sessions |
| API Key (ULID) | `Authorization: Bearer uF/pB/sF/tB...` | ULID-based with HMAC | Server-to-server |
| API Key (Alt) | `X-API-Key: <key>` | ULID-based with HMAC | Client-side |
| Internal Service | `X-Internal-Service-Token: <token>` | Service-to-service auth | Microservices |
| Session Token | `X-Session-Token: <token>` | Session-based auth | Web sessions |

#### Auth Context Methods (Detailed)

| Method | Type | Description |
|--------|------|-------------|
| `password` | Password | Traditional password authentication |
| `otp_email` | OTP | Email-based one-time password |
| `otp_sms` | OTP | SMS-based one-time password |
| `magic_link` | Magic Link | Email magic link verification |
| `passkey` | Passkey | FIDO2/WebAuthn passwordless |
| `oauth` | OAuth | External OAuth provider |

### POST `/v1/auth/attempt` - Authenticate User

**Description:** Single entry point for authentication (login/auto-create/resume)

**Authentication:** None (public)

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| x-tenant-id | Yes | Tenant UUID for context |

#### Password Authentication

```json
{
  "identity": "user@example.com",
  "authMethod": "password",
  "secret": "password123",
  "deviceFingerprint": "optional-device-fp",
  "userAgent": "Mozilla/5.0..."
}
```

#### OTP Authentication

```json
{
  "identity": "+1234567890",
  "authMethod": "otp",
  "secret": "123456",
  "deviceFingerprint": "optional-device-fp",
  "userAgent": "Mozilla/5.0..."
}
```

#### Magic Link Authentication

```json
{
  "identity": "user@example.com",
  "authMethod": "magic_link",
  "deviceFingerprint": "optional-device-fp",
  "userAgent": "Mozilla/5.0..."
}
```

#### OAuth Authentication

```json
{
  "identity": "google:google-subject-id",
  "authMethod": "oauth",
  "deviceFingerprint": "optional-device-fp",
  "userAgent": "Mozilla/5.0..."
}
```

#### Session Resumption (stateToken)

```json
{
  "stateToken": "base64-encoded-state-token",
  "deviceFingerprint": "optional-device-fp",
  "userAgent": "Mozilla/5.0..."
}
```

**Response (200 OK):**
```json
{
  "data": {
    "accessToken": "eyJ...",
    "refreshToken": "eyJ...",
    "expiresIn": 900,
    "tokenType": "Bearer",
    "principal": {
      "id": "uuid",
      "status": "active",
      "authMethodsSummary": []
    },
    "membership": {
      "id": "uuid",
      "tenantId": "uuid",
      "status": "active",
      "tenantType": "standard",
      "isolationTier": "standard"
    },
    "actor": {
      "id": "uuid",
      "type": "user",
      "displayName": "User Name",
      "isDefault": true
    }
  }
}
```

---

### POST `/v1/auth/profile/complete` - Complete User Profile

**Description:** Complete user profile after auto-create

**Headers:** x-tenant-id required

**Request Body:**
```json
{
  "stateToken": "state-token-from-attempt-response",
  "profileData": {
    "displayName": "John Doe",
    "phone": "+1234567890"
  }
}
```

---

### GET `/v1/auth/session/status` - Check Session Validity

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| stateToken | string | Yes | State token to validate |

---

### POST `/v1/auth/session/abandon` - Abandon Session

**Request Body:**
```json
{
  "stateToken": "state-token-to-abandon"
}
```

**Response:** `204 No Content`

---

## Core Auth (`/v1/auth`)

### POST `/v1/auth/signup` - Create Tenant Account

**Authentication:** None (public)

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "tenantName": "My Company",
  "domain": "mycompany.com"
}
```

**Response (201 Created):**
```json
{
  "data": {
    "userId": "uuid",
    "tenantId": "uuid",
    "email": "user@example.com",
    "status": "pending_verification"
  }
}
```

---

### POST `/v1/auth/login` - Authenticate

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

---

### POST `/v1/auth/refresh` - Refresh Token

**Request Body:**
```json
{
  "refreshToken": "eyJ..."
}
```

---

### POST `/v1/auth/logout` - Logout

**Authentication:** Required (Bearer)

---

### POST `/v1/auth/logout-all` - Logout All Sessions

**Authentication:** Required (Bearer)

---

### POST `/v1/auth/switch-actor` - Switch Actor

**Authentication:** Required (Bearer)

**Request Body:**
```json
{
  "targetActorId": "uuid",
  "reason": "Testing admin functionality"
}
```

---

### POST `/v1/auth/introspect` - Introspect Token

**Authentication:** Required (Bearer or API Key)

**Request Body:**
```json
{
  "token": "eyJ..."
}
```

---

## Password Auth (`/v1/auth/password`)

### POST `/v1/auth/password/change` - Change Password

**Authentication:** Required (JWT)

**Request Body:**
```json
{
  "currentPassword": "OldPass123!",
  "newPassword": "NewPass456!"
}
```

---

### POST `/v1/auth/password/reset/request` - Request Reset

**Authentication:** None

**Request Body:**
```json
{
  "identity": "user@example.com"
}
```

---

### POST `/v1/auth/password/reset/confirm` - Confirm Reset

**Request Body:**
```json
{
  "resetToken": "reset-token-from-email",
  "newPassword": "NewPass456!"
}
```

---

## OTP Auth (`/v1/auth/otp`)

### POST `/v1/auth/otp/send` - Send OTP

**Request Body:**
```json
{
  "userId": "uuid",
  "purpose": "IDENTITY_VERIFICATION",
  "recipient": "+1234567890",
  "channel": "SMS"
}
```

---

### POST `/v1/auth/otp/verify` - Verify OTP

**Request Body:**
```json
{
  "userId": "uuid",
  "code": "123456",
  "purpose": "IDENTITY_VERIFICATION"
}
```

---

## OAuth (`/v1/auth/oauth`)

### GET `/v1/auth/oauth/:provider` - Initiate OAuth

**Parameters:** provider = google, github, apple, microsoft

**Headers:** x-tenant-id required

---

### GET `/v1/auth/oauth/:provider/callback` - OAuth Callback

**Query Parameters:** code, state

---

## Users (`/v1/users/me`)

### GET `/v1/users/me` - Get Profile

**Authentication:** Required (Bearer)

---

### PATCH `/v1/users/me` - Update Profile

**Request Body:**
```json
{
  "displayName": "John Updated",
  "phone": "+1234567890",
  "avatarUrl": "https://example.com/avatar.jpg"
}
```

---

### DELETE `/v1/users/me` - Delete Account

**Authentication:** Required (Bearer)

---

### GET `/v1/users/me/identities` - List Identities

---

### POST `/v1/users/me/identities` - Add Identity

**Request Body:**
```json
{
  "provider": "google",
  "providerToken": "google-oauth-token"
}
```

---

### DELETE `/v1/users/me/identities/:provider` - Remove Identity

---

### GET `/v1/users/me/audit-logs` - Get Audit Logs

**Query Parameters:** limit, cursor, startDate, endDate, action

---

### GET `/v1/users/me/permissions` - Get Permissions

---

## Sessions (`/v1/users/me`)

### GET `/v1/users/me/sessions` - List Sessions

**Query Parameters:** limit, cursor

---

### DELETE `/v1/users/me/sessions/:id` - Revoke Session

**Response:** `204 No Content`

---

### GET `/v1/users/me/devices` - List Devices

---

### DELETE `/v1/users/me/devices/:id` - Remove Device

**Response:** `204 No Content`

---

## API Keys (`/v1/api-keys`)

### POST `/v1/api-keys` - Create API Key

**Request Body:**
```json
{
  "name": "Production API Key",
  "scope": "read",
  "tier": "standard",
  "ipAllowlist": ["192.168.1.0/24"],
  "rateLimit": 1000,
  "allowedOrigins": ["https://app.example.com"],
  "expiresInDays": 90
}
```

**Response (201 Created):**
```json
{
  "data": {
    "id": "uuid",
    "name": "Production API Key",
    "publishableKey": "uFxxxxxxxxxxxxxxxx",
    "secretKey": "sFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "scope": "read",
    "tier": "standard",
    "status": "active",
    "createdAt": "2025-01-15T10:30:00Z",
    "expiresAt": "2025-04-15T10:30:00Z"
  }
}
```

**Note:** `secretKey` is only returned once at creation time.

---

### GET `/v1/api-keys` - List API Keys

**Query Parameters:** limit, cursor, status

---

### GET `/v1/api-keys/:id` - Get API Key

---

### POST `/v1/api-keys/:id/rotate` - Rotate API Key

**Request Body:**
```json
{
  "gracePeriodSeconds": 3600
}
```

---

## Tenant API Keys (`/v1/tenant/api-keys`)

### POST `/v1/tenant/api-keys` - Create Tenant API Key

### GET `/v1/tenant/api-keys` - List Tenant API Keys

### GET `/v1/tenant/api-keys/:id` - Get Tenant API Key

### POST `/v1/tenant/api-keys/:id/rotate` - Rotate Tenant API Key

### POST `/v1/tenant/api-keys/:id/deprecate` - Deprecate Key

**Query Parameters:** gracePeriodSeconds

**Response:** `204 No Content`

### POST `/v1/tenant/api-keys/:id/revoke` - Revoke Key

**Response:** `204 No Content`

### PUT `/v1/tenant/api-keys/:id` - Update Key

### DELETE `/v1/tenant/api-keys/:id` - Delete Key

**Response:** `204 No Content`

---

## Policies (`/v1/policies`)

### POST `/v1/policies` - Create Policy

**Request Body:**
```json
{
  "name": "Admin Access Policy",
  "description": "Grants admin access during business hours",
  "rules": {
    "effect": "allow",
    "actions": ["read:*", "write:*"],
    "conditions": {
      "timeRange": {
        "start": "09:00",
        "end": "17:00",
        "timezone": "America/New_York"
      },
      "ipRange": ["192.168.1.0/24"]
    }
  }
}
```

---

### GET `/v1/policies` - List Policies

---

### DELETE `/v1/policies/:id` - Delete Policy

---

### POST `/v1/policies/:id/test` - Test Policy

**Request Body:**
```json
{
  "context": {
    "subject": "user-uuid",
    "action": "read:profile",
    "resource": "user:profile",
    "ipAddress": "192.168.1.100",
    "timestamp": "2025-01-15T14:00:00Z"
  }
}
```

---

## Roles (`/v1/roles`)

### POST `/v1/roles` - Create Role

**Request Body:**
```json
{
  "name": "Content Manager",
  "description": "Can manage content and media",
  "permissions": ["content:read", "content:write", "media:upload"]
}
```

---

### GET `/v1/roles` - List Roles

---

### POST `/v1/roles/assign` - Assign Role

**Request Body:**
```json
{
  "userId": "user-uuid",
  "roleId": "role-uuid",
  "expiresAt": "2025-12-31T23:59:59Z"
}
```

---

## Dynamic Modules (`/v1/modules`)

### GET `/v1/modules/:moduleKey/resources/:resourceKey` - Get Resource

### POST `/v1/modules/:moduleKey/commands/:commandKey` - Execute Command

### POST `/v1/modules/:moduleKey/actions/:actionKey` - Execute Action

---

## Extensions (`/v1/extensions`)

### GET `/v1/extensions/:extensionKey/schema` - Get Schema

### GET `/v1/extensions/:extensionKey/bindings` - Get Bindings

### POST `/v1/extensions/:extensionKey/commands/:commandKey` - Execute Extension

---

## Communication (`/v1`)

### POST `/v1/auth/otp/runtime/send` - Send OTP Runtime

### POST `/v1/auth/otp/retry` - Retry OTP

### POST `/v1/auth/otp/runtime/verify` - Verify OTP Runtime

### POST `/v1/auth/otp/widget/verify-token` - Verify Widget Token

### GET `/v1/auth/otp/challenges/:challengeId` - Get Challenge

### POST `/v1/communication/email/send` - Send Email

**Request Body:**
```json
{
  "to": ["user@example.com"],
  "cc": ["admin@example.com"],
  "subject": "Test Email",
  "html": "<h1>Hello</h1><p>This is a test email.</p>",
  "text": "Hello, this is a test email.",
  "from": "noreply@example.com",
  "templateId": "template-uuid",
  "variables": { "name": "John" }
}
```

---

### POST `/v1/communication/email/batch` - Send Batch Email

### GET `/v1/communication/templates` - List Templates

### POST `/v1/communication/templates` - Create Template

### POST `/v1/communication/webhooks/:provider` - Process Webhook

### GET `/v1/communication/deliveries/:lineageId` - Get Delivery

### GET `/v1/providers/health` - Get Provider Health

---

## OTP Widget (`/v1/auth/otp/widget`)

### GET `/v1/auth/otp/widget/config` - Get Widget Config

### POST `/v1/auth/otp/widget/send` - Send OTP Widget

### POST `/v1/auth/otp/widget/verify` - Verify OTP Widget

### POST `/v1/auth/otp/widget/retry` - Retry OTP Widget

### GET `/v1/auth/otp/widget/channels` - Get Channels

---

## Discovery (`.well-known`)

### GET `/.well-known/jwks.json` - JWKS

### GET `/.well-known/openid-configuration` - OIDC Discovery

---

## Admin (`/v1/admin`)

### GET `/v1/admin/health` - Admin Health

---

## Platform - Tenants (`/platform/v1/tenants`)

### POST `/platform/v1/tenants` - Create Tenant

**Authentication:** Platform API Key

**Request Body:**
```json
{
  "name": "New Company",
  "domain": "newcompany.com",
  "plan": "enterprise",
  "quota": {
    "apiCalls": 1000000,
    "storage": 100,
    "users": 1000,
    "domains": 5
  },
  "metadata": {}
}
```

---

### GET `/platform/v1/tenants` - List Tenants

**Query Parameters:** status, limit, offset

---

### GET `/platform/v1/tenants/:id` - Get Tenant

### PATCH `/platform/v1/tenants/:id` - Update Tenant

### PATCH `/platform/v1/tenants/:id/status` - Update Status

**Request Body:**
```json
{
  "status": "suspended",
  "reason": "Non-payment"
}
```

---

### DELETE `/platform/v1/tenants/:id` - Delete Tenant

**Response:** `204 No Content`

---

### POST `/platform/v1/tenants/:id/migrate` - Migrate Tenant

**Request Body:**
```json
{
  "targetRegion": "eu-west-1"
}
```

---

### POST `/platform/v1/tenants/:id/clone` - Clone Tenant

**Request Body:**
```json
{
  "newName": "Cloned Company"
}
```

---

### GET `/platform/v1/tenants/:id/usage` - Get Usage

### POST `/platform/v1/tenants/:id/quota` - Set Quota

---

## Platform - Impersonation (`/platform/v1/impersonate`)

### POST `/platform/v1/impersonate/sessions` - Start Impersonation

### DELETE `/platform/v1/impersonate/sessions/:id` - End Impersonation

### GET `/platform/v1/impersonate/sessions` - List Sessions

### GET `/platform/v1/impersonate/sessions/:id` - Get Session

### POST `/platform/v1/impersonate/sessions/:id/approve` - Approve

### POST `/platform/v1/impersonate/sessions/:id/reject` - Reject

---

## Platform - Security (`/platform/v1/security`)

### GET `/platform/v1/security/incidents` - List Incidents

### POST `/platform/v1/security/incidents` - Create Incident

### PATCH `/platform/v1/security/incidents/:id` - Update Incident

### GET `/platform/v1/security/threat-intel` - List Threat Intel

### POST `/platform/v1/security/threat-intel` - Add Threat

### POST `/platform/v1/security/threat-intel/check` - Check Threat

### GET `/platform/v1/security/risk-scores` - Get Risk Scores

### GET `/platform/v1/security/anomalies` - Get Anomalies

### POST `/platform/v1/security/analyze` - Trigger Analysis

### POST `/platform/v1/security/vulnerability-scan` - Run Scan

### GET `/platform/v1/security/vulnerability-scan/:scanId` - Get Scan Results

---

## Platform - Audit (`/platform/v1`)

### GET `/platform/v1/audit` - List Audit Logs

### GET `/platform/v1/audit/:id` - Get Audit Log

### GET `/platform/v1/audit/export` - Export Audit

### GET `/platform/v1/sign-ins` - List Sign-ins

### GET `/platform/v1/compliance/reports` - List Reports

### GET `/platform/v1/compliance/reports/:id` - Get Report

### POST `/platform/v1/compliance/reports` - Generate Report

---

## Platform - Governance (`/platform/v1`)

### POST `/platform/v1/identities` - Create Identity

### GET `/platform/v1/identities` - List Identities

### GET `/platform/v1/identities/:id` - Get Identity

### PATCH `/platform/v1/identities/:id/status` - Update Status

### POST `/platform/v1/identities/:id/api-keys` - Create API Key

### GET `/platform/v1/identities/:id/api-keys` - List API Keys

### GET `/platform/v1/roles` - List Roles

### GET `/platform/v1/roles/system` - List System Roles

### POST `/platform/v1/roles/bootstrap` - Bootstrap Roles

### POST `/platform/v1/identities/:id/roles` - Assign Role

### GET `/platform/v1/identities/:id/roles` - Get Identity Roles

### POST `/platform/v1/identities/:id/roles/activate` - Activate JIT Role

### GET `/platform/v1/identities/:id/permissions` - Get Permissions

---

## Platform - Regions (`/platform/v1/regions`)

### GET `/platform/v1/regions` - List Regions

### GET `/platform/v1/regions/:id` - Get Region

### POST `/platform/v1/regions` - Create Region

### PATCH `/platform/v1/regions/:id` - Update Region

### POST `/platform/v1/regions/:id/primary` - Set Primary

### POST `/platform/v1/regions/:id/failover` - Trigger Failover

### GET `/platform/v1/regions/failovers` - List Failovers

### GET `/platform/v1/regions/failovers/:id` - Get Failover

### POST `/platform/v1/regions/failovers/:id/complete` - Complete Failover

### GET `/platform/v1/regions/geo-routing` - List Geo-routing

### POST `/platform/v1/regions/geo-routing` - Create Geo-routing

### PATCH `/platform/v1/regions/geo-routing/:id` - Update Geo-routing

### GET `/platform/v1/regions/geo-routing/:countryCode` - Get Country Routing

---

## Platform - Resilience (`/platform/v1/resilience`)

### GET `/platform/v1/resilience/health` - Get Health

### GET `/platform/v1/resilience/health/:component` - Get Component Health

### GET `/platform/v1/resilience/incidents` - List Incidents

### GET `/platform/v1/resilience/incidents/:id` - Get Incident

### POST `/platform/v1/resilience/incidents` - Create Incident

### PATCH `/platform/v1/resilience/incidents/:id` - Update Incident

### GET `/platform/v1/resilience/circuit-breakers` - List CBs

### GET `/platform/v1/resilience/circuit-breakers/:service` - Get CB

### POST `/platform/v1/resilience/chaos/experiments` - Run Chaos

### GET `/platform/v1/resilience/chaos/experiments` - List Chaos

### GET `/platform/v1/resilience/chaos/experiments/:id` - Get Chaos

### PATCH `/platform/v1/resilience/chaos/experiments/:id` - Update Chaos

---

## Platform - Approvals (`/platform/v1/approvals`)

### GET `/platform/v1/approvals` - List Approvals

### POST `/platform/v1/approvals/request` - Request Approval

### POST `/platform/v1/approvals/:id/approve` - Approve

### POST `/platform/v1/approvals/:id/reject` - Reject

### POST `/platform/v1/approvals/:id/escalate` - Escalate

### GET `/platform/v1/approvals/pending` - Get Pending

---

## Platform - Data Governance (`/platform/v1`)

### GET `/platform/v1/consents` - List Consents

### POST `/platform/v1/consents` - Record Consent

### GET `/platform/v1/consents/:identityId` - Get Consents

### POST `/platform/v1/consents/:identityId/withdraw` - Withdraw Consent

### GET `/platform/v1/retention/policies` - List Retention Policies

### POST `/platform/v1/retention/policies` - Create Retention Policy

### PATCH `/platform/v1/retention/policies/:id` - Update Retention Policy

### POST `/platform/v1/retention/purge` - Trigger Purge

### POST `/platform/v1/dsar/requests` - Create DSAR Request

### GET `/platform/v1/dsar/requests` - List DSAR Requests

### GET `/platform/v1/dsar/requests/:id` - Get DSAR Request

### POST `/platform/v1/dsar/requests/:id/verify` - Verify DSAR

### POST `/platform/v1/dsar/requests/:id/complete` - Complete DSAR

### POST `/platform/v1/dsar/requests/:id/reject` - Reject DSAR

---

## Platform - Config (`/platform/v1`)

### GET `/platform/v1/config` - Get Config

### PATCH `/platform/v1/config` - Update Config

### POST `/platform/v1/config` - Create Config

### DELETE `/platform/v1/config/:key` - Delete Config

### GET `/platform/v1/config/history` - Get History

### POST `/platform/v1/config/rollback/:version` - Rollback

### GET `/platform/v1/announcements` - List Announcements

### POST `/platform/v1/announcements` - Create Announcement

### DELETE `/platform/v1/announcements/:id` - Delete Announcement

### POST `/platform/v1/config/export` - Export Config

### POST `/platform/v1/config/import` - Import Config

---

## Platform - DID/VC (`/platform/v1/identities`)

### POST `/platform/v1/identities/did/register` - Register DID

### GET `/platform/v1/identities/did/:did` - Resolve DID

### POST `/platform/v1/identities/vc/issue` - Issue VC

### POST `/platform/v1/identities/vc/verify` - Verify VC

### POST `/platform/v1/identities/vc/revoke` - Revoke VC

### GET `/platform/v1/identities/:id/credentials` - List Credentials

### POST `/platform/v1/identities/:id/link-did` - Link DID

---

## Platform - CA Policies (`/platform/v1/ca-policies`)

### GET `/platform/v1/ca-policies` - List CA Policies

### POST `/platform/v1/ca-policies` - Create CA Policy

### GET `/platform/v1/ca-policies/:id` - Get CA Policy

### PATCH `/platform/v1/ca-policies/:id` - Update CA Policy

### DELETE `/platform/v1/ca-policies/:id` - Delete CA Policy

### POST `/platform/v1/ca-policies/:id/test` - Test CA Policy

---

## Platform - ZT Policies (`/platform/v1`)

### GET `/platform/v1/zt-policies` - List ZT Policies

### POST `/platform/v1/zt-policies` - Create ZT Policy

### PUT `/platform/v1/zt-policies/:id/device` - Update Device Policy

### PUT `/platform/v1/zt-policies/:id/network` - Update Network Policy

### GET `/platform/v1/device-posture/:identity` - Get Device Posture

---

## Platform - Apps (`/v1/platform/apps`)

### GET `/v1/platform/apps/:id` - Get App

### POST `/v1/platform/apps` - Create App

---

## Platform - Apps Secrets (`/v1/platform/apps/:appId/secrets`)

### GET `/v1/platform/apps/:appId/secrets` - List Secrets

### POST `/v1/platform/apps/:appId/secrets` - Create Secret

---

## Platform - Domains (`/v1/platform/domains`)

### GET `/v1/platform/domains/:domain` - Get Domain

### POST `/v1/platform/domains` - Create Domain

---

## Platform - OAuth (`/v1/platform/oauth`)

### GET `/v1/platform/oauth/authorize` - OAuth Authorize

### POST `/v1/platform/oauth/token` - OAuth Token

---

## Platform - Webhooks (`/v1/platform/webhooks`)

### GET `/v1/platform/webhooks/:id` - Get Webhook

### POST `/v1/platform/webhooks` - Create Webhook

---

## Health

### GET `/health` - Health Check

### GET `/health/live` - Liveness Probe

### GET `/health/ready` - Readiness Probe

---

## Error Response Format

All errors follow a consistent format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable message",
    "details": [
      {
        "field": "email",
        "message": "Must be a valid email address",
        "code": "invalid_format"
      }
    ]
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Authenticated but not authorized |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource already exists |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

---

## Rate Limiting

Rate limit headers included in responses:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1640000000
```

When exceeded:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

---

## AI Context & Knowledge Graph

### Machine-Readable Architecture Summary

```json
{
  "system": "UICP",
  "architecture": "hexagonal",
  "pattern": "cqrs",
  "auth_model": "api_key_centric",
  "tenant_resolution": "credential_based",
  "queue_model": "bullmq",
  "trust_model": "zero_trust",
  "replay_protection": "idempotency_keys",
  "provider_routing": "smart_selection",
  "language": "typescript",
  "framework": "nestjs",
  "database": "mysql_8.0",
  "cache": "redis_6.0",
  "queue": "bullmq",
  "version": "1.0.0"
}
```

### Trust Boundaries

| Boundary | Trusted | Description |
|----------|---------|-------------|
| Client Applications | ⚠️ Conditional | Valid Bearer tokens only |
| API Gateway | ✅ Trusted | UnifiedAuthGuard validates all |
| Tenant Layer | ✅ Trusted | Tenant ID from credential |
| Application Services | ✅ Trusted | Business logic layer |
| Infrastructure | ⚠️ Conditional | MySQL, Redis, Queue |

### Runtime Dependencies

| Service | Depends On | Failure Impact |
|---------|------------|-----------------|
| API Gateway | JWT Guard, Redis | All API access |
| Auth Service | User Repo, Token Svc | Login failures |
| Token Service | JWT Secret, Redis | Session validation |
| API Key Service | Key Repo, HMAC Secret | Tenant resolution |
| Communication | Provider Router, Queues | Email/SMS delivery |
| OTP Service | OTP Repo, Communication | MFA failures |

### Failure Models

| Failure | Symptoms | Mitigation |
|---------|----------|------------|
| **MySQL Outage** | All write operations fail | Read replicas, connection pool |
| **Redis Degradation** | Session loss, rate limit bypass | In-memory fallback, circuit breaker |
| **Provider Outage** | Email/SMS delivery fails | Auto-failover chain |
| **Queue Storm** | Message backlog, timeout | Dead letter queue, backpressure |
| **Replay Attack** | Duplicate authentication | Idempotency keys, nonce validation |
| **JWT Compromise** | Unauthorized access | Token revocation list, emergency rotation |

### Queue Topology

| Queue | Priority | Retry Policy | DLQ |
|-------|----------|--------------|-----|
| `email-delivery` | MEDIUM | 3x exponential | yes |
| `sms-delivery` | HIGH | 3x exponential | yes |
| `otp-fastlane` | CRITICAL | 1x immediate | no |
| `webhook-processing` | LOW | 5x linear | yes |
| `audit-logging` | LOW | 3x exponential | yes |

### Provider Selection Rules

```
Priority Order:
1. Region match (lowest latency)
2. Cost optimization (cheapest within SLA)
3. Quota availability (has capacity)
4. Health score (highest available)
5. Fallback to configured default
```

### Operational Constraints

| Constraint | Value | Description |
|------------|-------|-------------|
| Max JWT Age | 900s | 15 minutes access token |
| Max Session Age | 86400s | 24 hours |
| OTP TTL | 300s | 5 minutes |
| API Key Grace Period | 3600s | 1 hour on rotation |
| Rate Limit Default | 1000/min | Per API key |

### Related Documentation Structure

```
docs/
├── 00-platform/          # Platform overview (THIS FILE)
├── 01-architecture/      # System architecture
├── 02-runtime/           # Request lifecycle
├── 03-auth/              # Authentication flows
├── 04-communication/     # Provider routing
├── 05-security/          # Zero-trust model
├── 06-sdk/              # SDK documentation
├── 07-api/              # API contracts
├── 08-data/             # Schema & persistence
├── 09-queues/           # Queue topology
├── 10-observability/    # Tracing & metrics
├── 11-operations/        # Runbooks
├── 12-testing/          # Test strategies
├── 13-ai-context/        # AI-readable summaries
├── 14-knowledge-graph/   # JSON topology graphs
├── 15-runtime-lineage/   # Request traceability
├── 16-failure-models/    # Failure scenarios
├── 17-adrs/             # Architecture decisions
└── 18-smart-tuning/     # Adaptive optimization
```

### Replay Safety Rules

1. **All mutations require idempotency key** - Prevents duplicate operations
2. **Token refresh requires rotation** - Old tokens invalidated
3. **Session recreation requires invalidation** - Previous sessions terminated
4. **API key rotation has grace period** - Old key valid during transition

### Security Invariants

1. Tenant ID NEVER derived from request header (only from credential)
2. HMAC validation required for all secret API keys
3. Rate limits enforced per API key, not per IP
4. Audit logs immutable (append-only event store)
5. Emergency revocation instant (Redis cache purge)

---

*Last Updated: 2026-05-15 | AI-Ingestible: true | Version: 1.0.0*