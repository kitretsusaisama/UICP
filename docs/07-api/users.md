# Users API

## Metadata
```yaml
title: Users API
domain: api
owner: identity-team
criticality: HIGH
runtime-impact: medium
security-impact: CRITICAL
queue-impact: none
provider-impact: none
tenant-impact: isolated
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - authentication.md
  - sessions.md
related-docs:
  - authentication.md
  - sessions.md
  - organizations.md
related-queues: []
related-services:
  - UserRepository
  - IdentityRepository
```

---

## Overview

The Users API provides endpoints for managing user accounts within a tenant. All operations are scoped to the authenticated tenant context. Users can be created, retrieved, updated, listed, and deleted.

---

## Endpoints

### Create User

**POST** `/api/v1/users`

Create a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "secure-password-123",
  "firstName": "John",
  "lastName": "Doe",
  "role": "member",
  "metadata": {
    "department": "engineering"
  }
}
```

**Response (201):**
```json
{
  "userId": "ulid-string",
  "email": "user@example.com",
  "username": "johndoe",
  "firstName": "John",
  "lastName": "Doe",
  "role": "member",
  "status": "active",
  "createdAt": "2026-05-16T10:00:00Z",
  "updatedAt": "2026-05-16T10:00:00Z"
}
```

**Response (409):** Email or username already exists

---

### Get User

**GET** `/api/v1/users/{userId}`

Retrieve user details by ID.

**Response (200):**
```json
{
  "userId": "ulid-string",
  "email": "user@example.com",
  "username": "johndoe",
  "firstName": "John",
  "lastName": "Doe",
  "role": "member",
  "status": "active",
  "createdAt": "2026-05-16T10:00:00Z",
  "updatedAt": "2026-05-16T10:00:00Z",
  "lastLoginAt": "2026-05-16T11:30:00Z"
}
```

**Response (404):** User not found

---

### Update User

**PATCH** `/api/v1/users/{userId}`

Update user profile or role.

**Request:**
```json
{
  "firstName": "Jane",
  "role": "admin",
  "metadata": {"department": "product"}
}
```

**Response (200):**
```json
{
  "userId": "ulid-string",
  "email": "user@example.com",
  "firstName": "Jane",
  "role": "admin",
  "updatedAt": "2026-05-16T12:00:00Z"
}
```

---

### List Users

**GET** `/api/v1/users`

List all users in the tenant.

**Query Parameters:**
- `limit` (integer, default: 20, max: 100)
- `offset` (integer, default: 0)
- `status` (string: active, inactive, suspended)
- `role` (string: admin, member, viewer)
- `search` (string) - search by email or username

**Response (200):**
```json
{
  "users": [
    {
      "userId": "ulid-string",
      "email": "user@example.com",
      "username": "johndoe",
      "role": "member",
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

### Delete User

**DELETE** `/api/v1/users/{userId}`

Soft-delete a user account (marks as deleted).

**Response (204):** Successfully deleted

**Response (409):** Cannot delete user with active sessions

---

### Change Password

**POST** `/api/v1/users/{userId}/password`

Change user password.

**Request:**
```json
{
  "currentPassword": "old-password",
  "newPassword": "new-secure-password-456"
}
```

**Response (200):** Password changed successfully

**Response (401):** Current password incorrect

---

## User Data Model

| Field | Type | Description |
|-------|------|-------------|
| userId | ULID | Unique user identifier |
| email | string | User email (unique per tenant) |
| username | string | Username (unique per tenant) |
| password | string | Encrypted password hash |
| firstName | string | First name |
| lastName | string | Last name |
| role | enum | admin, member, viewer |
| status | enum | active, inactive, suspended, deleted |
| metadata | object | Custom key-value pairs |
| createdAt | ISO8601 | Creation timestamp |
| updatedAt | ISO8601 | Last update timestamp |
| lastLoginAt | ISO8601 | Last login timestamp |

---

## Rate Limits

- Create user: 10 requests/minute per tenant
- List users: 30 requests/minute per tenant
- Get/Update/Delete: 60 requests/minute per user