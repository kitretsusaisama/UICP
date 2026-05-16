# Admin API

## Metadata
```yaml
title: Admin API
domain: api
owner: admin-team
criticality: CRITICAL
runtime-impact: high
security-impact: CRITICAL
queue-impact: medium
provider-impact: none
tenant-impact: cross-tenant
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - authentication.md
  - platform.md
related-docs:
  - platform.md
  - errors.md
  - audit.md
related-queues:
  - admin-operations
related-services:
  - AdminService
  - AuditService
  - KmsService
```

---

## Overview

The Admin API provides system-level operations for platform administrators. These endpoints require elevated privileges and are subject to strict access controls and audit logging. Cross-tenant operations affect all tenants.

---

## Endpoints

### System Health

**GET** `/api/v1/admin/health`

Get overall system health status.

**Response (200):**
```json
{
  "status": "healthy",
  "components": {
    "database": "healthy",
    "cache": "healthy",
    "queue": "healthy",
    "providers": "degraded"
  },
  "uptime": 86400000,
  "timestamp": "2026-05-16T10:00:00Z"
}
```

---

### List All Tenants

**GET** `/api/v1/admin/tenants`

List all tenants in the system (super-admin only).

**Query Parameters:**
- `limit` (integer, default: 20, max: 100)
- `offset` (integer, default: 0)
- `status` (string: active, suspended, deleted)
- `tier` (string: free, starter, professional, enterprise)

**Response (200):**
```json
{
  "tenants": [
    {
      "tenantId": "ulid-string",
      "name": "Acme Corp",
      "slug": "acme-corp",
      "tier": "enterprise",
      "status": "active",
      "createdAt": "2026-05-01T00:00:00Z"
    }
  ],
  "total": 50,
  "limit": 20,
  "offset": 0
}
```

---

### Suspend Tenant

**POST** `/api/v1/admin/tenants/{tenantId}/suspend`

Suspend a tenant's access.

**Request:**
```json
{
  "reason": "Payment overdue",
  "duration": 86400000
}
```

**Response (200):** Tenant suspended

---

### Resume Tenant

**POST** `/api/v1/admin/tenants/{tenantId}/resume`

Resume a suspended tenant.

**Response (200):** Tenant resumed

---

### View Audit Logs

**GET** `/api/v1/admin/audit-logs`

Query platform-wide audit logs.

**Query Parameters:**
- `startDate` (ISO8601)
- `endDate` (ISO8601)
- `actorId` (ULID)
- `action` (string)
- `tenantId` (ULID)
- `limit` (integer, default: 50, max: 200)

**Response (200):**
```json
{
  "logs": [
    {
      "logId": "ulid-string",
      "timestamp": "2026-05-16T10:00:00Z",
      "actorId": "ulid-string",
      "actorType": "admin",
      "action": "tenant.suspend",
      "tenantId": "ulid-string",
      "details": {"reason": "Payment overdue"}
    }
  ],
  "total": 100
}
```

---

### Manage API Keys (Cross-Tenant)

**GET** `/api/v1/admin/api-keys`

List all API keys across all tenants.

**Query Parameters:**
- `tenantId` (ULID)
- `status` (string: active, revoked, expired)

**Response (200):** API key list

---

### Revoke API Key (Cross-Tenant)

**DELETE** `/api/v1/admin/api-keys/{apiKeyId}`

Revoke any API key in the system.

**Response (204):** API key revoked

---

### Platform Configuration

**GET** `/api/v1/admin/config`

Get platform configuration.

**Response (200):**
```json
{
  "features": {
    "allowPublicSignup": true,
    "requireEmailVerification": true,
    "allowApiKeyAccess": true
  },
  "rateLimits": {
    "default": 1000,
    "enterprise": 10000
  },
  "providers": {
    "email": ["sendgrid", "aws-ses"],
    "sms": ["twilio", "aws-sns"]
  }
}
```

---

### Update Platform Configuration

**PATCH** `/api/v1/admin/config`

Update platform-wide settings.

**Request:**
```json
{
  "features": {
    "allowPublicSignup": false
  }
}
```

**Response (200):** Configuration updated

---

## Admin Roles

| Role | Permissions |
|------|-------------|
| super-admin | Full system access, cross-tenant operations |
| admin | Tenant management within assigned scope |
| auditor | Read-only audit log access |

---

## Rate Limits

- Health check: 60 requests/minute
- Tenant operations: 10 requests/minute
- Audit logs: 30 requests/minute
- Configuration: 5 requests/minute

---

## Audit Requirements

All admin operations are logged with:
- Actor identity
- Timestamp (UTC)
- Action type
- Target tenant/resource
- Request details
- Response status