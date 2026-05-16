# Providers API

## Metadata
```yaml
title: Providers API
domain: api
owner: platform-team
criticality: HIGH
runtime-impact: medium
security-impact: MEDIUM
queue-impact: medium
provider-impact: high
tenant-impact: isolated
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - authentication.md
  - platform.md
related-docs:
  - platform.md
  - communication.md
related-queues:
  - provider-routing
  - provider-failover
related-services:
  - ProviderRoutingService
  - ProviderRepository
```

---

## Overview

The Providers API manages external service provider integrations including email, SMS, payment, and AI providers. It supports provider configuration, routing rules, failover policies, and health monitoring.

---

## Endpoints

### List Providers

**GET** `/api/v1/providers`

List all configured providers for the tenant.

**Query Parameters:**
- `type` (string: email, sms, payment, ai)
- `status` (string: active, inactive, degraded)

**Response (200):**
```json
{
  "providers": [
    {
      "providerId": "ulid-string",
      "name": "SendGrid Primary",
      "type": "email",
      "status": "active",
      "priority": 1,
      "config": {
        "apiKey": "***",
        "webhookUrl": "https://..."
      },
      "health": {
        "status": "healthy",
        "lastCheck": "2026-05-16T10:00:00Z",
        "avgLatency": 45
      }
    }
  ]
}
```

---

### Get Provider Details

**GET** `/api/v1/providers/{providerId}`

Get detailed provider information including configuration.

**Response (200):**
```json
{
  "providerId": "ulid-string",
  "name": "SendGrid Primary",
  "type": "email",
  "status": "active",
  "priority": 1,
  "config": {
    "apiKey": "***",
    "webhookUrl": "https://...",
    "fromAddress": "noreply@company.com"
  },
  "routingRules": {
    "geoRouting": false,
    "loadBalancing": "round-robin"
  },
  "failoverConfig": {
    "enabled": true,
    "failoverDelay": 5000,
    "maxRetries": 3
  },
  "health": {
    "status": "healthy",
    "lastCheck": "2026-05-16T10:00:00Z",
    "avgLatency": 45,
    "successRate": 99.8
  }
}
```

---

### Create Provider

**POST** `/api/v1/providers`

Register a new provider integration.

**Request:**
```json
{
  "name": "Twilio SMS",
  "type": "sms",
  "config": {
    "accountSid": "ACxxxxx",
    "authToken": "***",
    "fromNumber": "+15551234567"
  },
  "routingRules": {
    "loadBalancing": "least-connections"
  },
  "failoverConfig": {
    "enabled": true,
    "maxRetries": 3
  }
}
```

**Response (201):**
```json
{
  "providerId": "ulid-string",
  "name": "Twilio SMS",
  "type": "sms",
  "status": "active",
  "createdAt": "2026-05-16T10:00:00Z"
}
```

---

### Update Provider

**PATCH** `/api/v1/providers/{providerId}`

Update provider configuration or settings.

**Request:**
```json
{
  "priority": 2,
  "status": "inactive",
  "failoverConfig": {
    "maxRetries": 5
  }
}
```

**Response (200):** Provider updated

---

### Delete Provider

**DELETE** `/api/v1/providers/{providerId}`

Remove a provider configuration.

**Response (204):** Provider deleted

**Response (409):** Provider in use by active routing rules

---

### Test Provider

**POST** `/api/v1/providers/{providerId}/test`

Send a test message through the provider.

**Request:**
```json
{
  "type": "email",
  "to": "test@example.com",
  "subject": "Test Message",
  "body": "This is a test"
}
```

**Response (200):**
```json
{
  "success": true,
  "latency": 120,
  "message": "Test message sent successfully"
}
```

---

### Get Provider Metrics

**GET** `/api/v1/providers/{providerId}/metrics`

Retrieve performance metrics for a provider.

**Query Parameters:**
- `startDate` (ISO8601)
- `endDate` (ISO8601)
- `granularity` (string: minute, hour, day)

**Response (200):**
```json
{
  "providerId": "ulid-string",
  "period": {
    "start": "2026-05-01T00:00:00Z",
    "end": "2026-05-16T00:00:00Z"
  },
  "metrics": {
    "totalRequests": 50000,
    "successfulRequests": 49750,
    "failedRequests": 250,
    "avgLatency": 125,
    "p95Latency": 200,
    "successRate": 99.5
  }
}
```

---

## Provider Data Model

| Field | Type | Description |
|-------|------|-------------|
| providerId | ULID | Unique provider identifier |
| name | string | Display name |
| type | enum | email, sms, payment, ai |
| status | enum | active, inactive, degraded |
| priority | integer | Routing priority (lower = higher) |
| config | object | Provider-specific configuration |
| routingRules | object | Routing configuration |
| failoverConfig | object | Failover settings |
| health | object | Health check results |

---

## Rate Limits

- List providers: 30 requests/minute
- Create provider: 10 requests/minute
- Test provider: 5 requests/minute
- Get metrics: 20 requests/minute