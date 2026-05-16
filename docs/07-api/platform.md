# Platform API

## Metadata
```yaml
title: Platform API
domain: api
owner: platform-team
criticality: HIGH
runtime-impact: high
security-impact: MEDIUM
queue-impact: medium
provider-impact: medium
tenant-impact: isolated
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - authentication.md
  - admin.md
related-docs:
  - admin.md
  - providers.md
related-queues:
  - platform-operations
  - kms-operations
related-services:
  - KmsService
  - ExtensionExecutor
  - ManifestService
```

---

## Overview

The Platform API provides endpoints for managing platform-level resources including key management, extensions, manifests, and runtime configurations. These operations affect individual tenants but are scoped to the authenticated tenant context.

---

## Endpoints

### Key Management (KMS)

**POST** `/api/v1/platform/keys`

Generate a new encryption key.

**Request:**
```json
{
  "keyType": "symmetric",
  "algorithm": "AES-256-GCM",
  "purpose": "data-encryption",
  "rotationPolicy": {
    "enabled": true,
    "intervalDays": 90
  }
}
```

**Response (201):**
```json
{
  "keyId": "ulid-string",
  "status": "active",
  "createdAt": "2026-05-16T10:00:00Z",
  "expiresAt": "2026-08-14T10:00:00Z"
}
```

---

### List Keys

**GET** `/api/v1/platform/keys`

List all keys in the tenant.

**Response (200):**
```json
{
  "keys": [
    {
      "keyId": "ulid-string",
      "keyType": "symmetric",
      "algorithm": "AES-256-GCM",
      "status": "active",
      "createdAt": "2026-05-16T10:00:00Z",
      "expiresAt": "2026-08-14T10:00:00Z"
    }
  ]
}
```

---

### Encrypt Data

**POST** `/api/v1/platform/encrypt`

Encrypt data using tenant keys.

**Request:**
```json
{
  "keyId": "ulid-string",
  "plaintext": "base64-encoded-data"
}
```

**Response (200):**
```json
{
  "ciphertext": "base64-encoded-ciphertext",
  "keyId": "ulid-string",
  "algorithm": "AES-256-GCM"
}
```

---

### Decrypt Data

**POST** `/api/v1/platform/decrypt`

Decrypt data using tenant keys.

**Request:**
```json
{
  "keyId": "ulid-string",
  "ciphertext": "base64-encoded-ciphertext"
}
```

**Response (200):**
```json
{
  "plaintext": "base64-encoded-data",
  "keyId": "ulid-string"
}
```

---

### Extensions

**GET** `/api/v1/platform/extensions`

List available platform extensions.

**Response (200):**
```json
{
  "extensions": [
    {
      "extensionId": "ulid-string",
      "name": "Custom Auth Handler",
      "type": "auth-hook",
      "version": "1.0.0",
      "enabled": true
    }
  ]
}
```

---

### Execute Extension

**POST** `/api/v1/platform/extensions/{extensionId}/execute`

Execute a custom extension.

**Request:**
```json
{
  "hook": "pre-auth",
  "context": {
    "email": "user@example.com",
    "ip": "192.168.1.1"
  }
}
```

**Response (200):**
```json
{
  "success": true,
  "result": {
    "allow": true
  }
}
```

---

### Manifest Management

**GET** `/api/v1/platform/manifests`

List platform manifests.

**Response (200):**
```json
{
  "manifests": [
    {
      "manifestId": "ulid-string",
      "name": "default-api",
      "version": "1.0.0",
      "spec": "openapi-3.0"
    }
  ]
}
```

---

### Runtime Configuration

**GET** `/api/v1/platform/runtime/config`

Get runtime configuration for the tenant.

**Response (200):**
```json
{
  "features": {
    "betaFeatures": false,
    "debugMode": false
  },
  "limits": {
    "maxRequestSize": 10485760,
    "maxConcurrentRequests": 100
  },
  "environment": "production"
}
```

---

## Platform Data Model

| Field | Type | Description |
|-------|------|-------------|
| keyId | ULID | Unique key identifier |
| keyType | enum | symmetric, asymmetric |
| algorithm | string | Encryption algorithm |
| status | enum | active, suspended, expired |
| rotationPolicy | object | Key rotation settings |
| createdAt | ISO8601 | Creation timestamp |
| expiresAt | ISO8601 | Expiration timestamp |

---

## Rate Limits

- Key operations: 20 requests/minute
- Encrypt/Decrypt: 100 requests/minute
- Extensions: 30 requests/minute
- Manifests: 20 requests/minute