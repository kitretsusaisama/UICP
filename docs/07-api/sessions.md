# Session Management API

## Metadata
```yaml
title: Session Management
domain: api
owner: identity-team
criticality: HIGH
runtime-impact: low
security-impact: CRITICAL
queue-impact: none
provider-impact: none
tenant-impact: isolated
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - authentication.md
related-docs:
  - authentication.md
  - users.md
related-queues: []
related-services:
  - RedisCacheAdapter
  - SessionRepository
```

---

## Overview

The Session Management API provides endpoints to create, retrieve, list, and revoke user sessions. Sessions are stored in Redis with configurable TTL and support for concurrent session limits per user.

---

## Endpoints

### Create Session

**POST** `/api/v1/sessions`

Create a new authenticated session for a user.

**Request:**
```json
{
  "userId": "ulid-string",
  "expiresIn": 3600,
  "metadata": {
    "ip": "192.168.1.1",
    "userAgent": "Mozilla/5.0..."
  }
}
```

**Response (201):**
```json
{
  "sessionId": "session-ulid",
  "token": "session-xxxxx",
  "expiresAt": "2026-05-16T12:00:00Z",
  "refreshToken": "refresh-xxxxx"
}
```

**Response (409):** Session limit exceeded

---

### Get Session

**GET** `/api/v1/sessions/{sessionId}`

Retrieve session details by ID.

**Response (200):**
```json
{
  "sessionId": "session-ulid",
  "userId": "ulid-string",
  "createdAt": "2026-05-16T10:00:00Z",
  "expiresAt": "2026-05-16T12:00:00Z",
  "lastAccessedAt": "2026-05-16T11:30:00Z",
  "metadata": {
    "ip": "192.168.1.1"
  }
}
```

**Response (404):** Session not found

---

### List User Sessions

**GET** `/api/v1/users/{userId}/sessions`

List all active sessions for a specific user.

**Query Parameters:**
- `limit` (integer, default: 20, max: 100)
- `offset` (integer, default: 0)

**Response (200):**
```json
{
  "sessions": [
    {
      "sessionId": "session-ulid",
      "createdAt": "2026-05-16T10:00:00Z",
      "expiresAt": "2026-05-16T12:00:00Z",
      "metadata": {"ip": "192.168.1.1"}
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

---

### Revoke Session

**DELETE** `/api/v1/sessions/{sessionId}`

Revoke a single session.

**Response (204):** Successfully revoked

**Response (404):** Session not found

---

### Revoke All User Sessions

**DELETE** `/api/v1/users/{userId}/sessions`

Revoke all sessions for a user (logout everywhere).

**Response (204):** All sessions revoked

---

## Session Data Model

| Field | Type | Description |
|-------|------|-------------|
| sessionId | ULID | Unique session identifier |
| userId | ULID | Associated user ID |
| token | string | Opaque session token |
| refreshToken | string | Token for session refresh |
| createdAt | ISO8601 | Creation timestamp |
| expiresAt | ISO8601 | Expiration timestamp |
| lastAccessedAt | ISO8601 | Last activity timestamp |
| metadata | object | Client-provided context |

---

## Rate Limits

- Create session: 10 requests/minute per user
- List sessions: 30 requests/minute per user
- Revoke: 20 requests/minute per user