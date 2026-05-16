# Organizations API

## Metadata
```yaml
title: Organizations API
domain: api
owner: identity-team
criticality: HIGH
runtime-impact: medium
security-impact: HIGH
queue-impact: none
provider-impact: none
tenant-impact: isolated
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - authentication.md
  - users.md
related-docs:
  - authentication.md
  - users.md
  - platform.md
related-queues: []
related-services:
  - TenantRepository
  - IdentityRepository
```

---

## Overview

The Organizations API provides endpoints for managing tenant organizations. Each organization represents a separate tenant with its own users, configuration, and billing. Organizations can have hierarchical structures with parent-child relationships.

---

## Endpoints

### Create Organization

**POST** `/api/v1/organizations`

Create a new organization (tenant).

**Request:**
```json
{
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "tier": "enterprise",
  "settings": {
    "allowPublicAccess": false,
    "sessionTimeout": 3600,
    "maxUsers": 100
  },
  "metadata": {
    "industry": "technology"
  }
}
```

**Response (201):**
```json
{
  "organizationId": "ulid-string",
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "tier": "enterprise",
  "status": "active",
  "settings": {
    "allowPublicAccess": false,
    "sessionTimeout": 3600,
    "maxUsers": 100
  },
  "createdAt": "2026-05-16T10:00:00Z",
  "updatedAt": "2026-05-16T10:00:00Z"
}
```

**Response (409):** Organization slug already exists

---

### Get Organization

**GET** `/api/v1/organizations/{organizationId}`

Retrieve organization details.

**Response (200):**
```json
{
  "organizationId": "ulid-string",
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "tier": "enterprise",
  "status": "active",
  "settings": {
    "allowPublicAccess": false,
    "sessionTimeout": 3600,
    "maxUsers": 100
  },
  "createdAt": "2026-05-16T10:00:00Z",
  "updatedAt": "2026-05-16T10:00:00Z"
}
```

---

### Update Organization

**PATCH** `/api/v1/organizations/{organizationId}`

Update organization settings or metadata.

**Request:**
```json
{
  "name": "Acme Inc",
  "settings": {
    "maxUsers": 500
  }
}
```

**Response (200):** Updated organization details

---

### List Organizations

**GET** `/api/v1/organizations`

List organizations (admin only, multi-tenant context).

**Query Parameters:**
- `limit` (integer, default: 20, max: 100)
- `offset` (integer, default: 0)
- `tier` (string: free, starter, professional, enterprise)
- `status` (string: active, suspended, deleted)

**Response (200):**
```json
{
  "organizations": [
    {
      "organizationId": "ulid-string",
      "name": "Acme Corporation",
      "slug": "acme-corp",
      "tier": "enterprise",
      "status": "active",
      "createdAt": "2026-05-16T10:00:00Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

---

### Create Organization Member

**POST** `/api/v1/organizations/{organizationId}/members`

Add a user to an organization.

**Request:**
```json
{
  "userId": "ulid-string",
  "role": "admin"
}
```

**Response (201):**
```json
{
  "memberId": "ulid-string",
  "userId": "ulid-string",
  "organizationId": "ulid-string",
  "role": "admin",
  "joinedAt": "2026-05-16T10:00:00Z"
}
```

---

### Remove Organization Member

**DELETE** `/api/v1/organizations/{organizationId}/members/{memberId}`

Remove a member from an organization.

**Response (204):** Member removed

---

### Get Organization Usage

**GET** `/api/v1/organizations/{organizationId}/usage`

Get current resource usage for the organization.

**Response (200):**
```json
{
  "users": {
    "current": 45,
    "limit": 100
  },
  "apiKeys": {
    "current": 12,
    "limit": 50
  },
  "storage": {
    "current": 1073741824,
    "limit": 5368709120
  },
  "period": {
    "start": "2026-05-01T00:00:00Z",
    "end": "2026-05-31T23:59:59Z"
  }
}
```

---

## Organization Data Model

| Field | Type | Description |
|-------|------|-------------|
| organizationId | ULID | Unique organization identifier |
| name | string | Display name |
| slug | string | URL-friendly identifier (unique) |
| tier | enum | free, starter, professional, enterprise |
| status | enum | active, suspended, deleted |
| settings | object | Organization-specific configuration |
| metadata | object | Custom key-value pairs |
| createdAt | ISO8601 | Creation timestamp |
| updatedAt | ISO8601 | Last update timestamp |

---

## Rate Limits

- Create organization: 5 requests/minute (admin)
- List organizations: 10 requests/minute (admin)
- Update settings: 20 requests/minute
- Member management: 30 requests/minute