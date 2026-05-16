# Webhooks API

## Metadata
```yaml
title: Webhooks API
domain: api
owner: integration-team
criticality: HIGH
runtime-impact: medium
security-impact: MEDIUM
queue-impact: medium
provider-impact: none
tenant-impact: isolated
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - authentication.md
  - platform.md
related-docs:
  - platform.md
  - errors.md
related-queues:
  - webhook-outbound
  - webhook-retry
related-services:
  - WebhookService
  - QueueAdapter
```

---

## Overview

The Webhooks API enables tenants to configure HTTP callbacks for system events. Webhooks support custom payloads, signing, retry logic, and event filtering. All webhook deliveries are logged and can be replayed on failure.

---

## Endpoints

### List Webhooks

**GET** `/api/v1/webhooks`

List all configured webhooks.

**Response (200):**
```json
{
  "webhooks": [
    {
      "webhookId": "ulid-string",
      "name": "Payment Notifications",
      "url": "https://example.com/webhooks/payment",
      "events": ["payment.completed", "payment.failed"],
      "status": "active",
      "secret": "***",
      "createdAt": "2026-05-16T10:00:00Z"
    }
  ]
}
```

---

### Create Webhook

**POST** `/api/v1/webhooks`

Register a new webhook endpoint.

**Request:**
```json
{
  "name": "Order Updates",
  "url": "https://example.com/webhooks/orders",
  "events": ["order.created", "order.updated", "order.completed"],
  "secret": "whsec-abc123",
  "headers": {
    "X-Custom-Header": "value"
  },
  "retryConfig": {
    "enabled": true,
    "maxRetries": 3,
    "retryInterval": 60000
  }
}
```

**Response (201):**
```json
{
  "webhookId": "ulid-string",
  "name": "Order Updates",
  "url": "https://example.com/webhooks/orders",
  "events": ["order.created", "order.updated", "order.completed"],
  "status": "active",
  "createdAt": "2026-05-16T10:00:00Z"
}
```

---

### Update Webhook

**PATCH** `/api/v1/webhooks/{webhookId}`

Update webhook configuration.

**Request:**
```json
{
  "name": "Order & Payment Updates",
  "events": ["order.created", "payment.completed"],
  "status": "inactive"
}
```

**Response (200):** Webhook updated

---

### Delete Webhook

**DELETE** `/api/v1/webhooks/{webhookId}`

Remove a webhook configuration.

**Response (204):** Webhook deleted

---

### Test Webhook

**POST** `/api/v1/webhooks/{webhookId}/test`

Send a test event to the webhook URL.

**Response (200):**
```json
{
  "success": true,
  "statusCode": 200,
  "latency": 250,
  "responseBody": "OK"
}
```

---

### Get Webhook Deliveries

**GET** `/api/v1/webhooks/{webhookId}/deliveries`

List webhook delivery attempts.

**Query Parameters:**
- `status` (string: success, failed, pending)
- `limit` (integer, default: 20, max: 100)
- `offset` (integer, default: 0)

**Response (200):**
```json
{
  "deliveries": [
    {
      "deliveryId": "ulid-string",
      "event": "order.created",
      "status": "success",
      "statusCode": 200,
      "latency": 250,
      "timestamp": "2026-05-16T10:00:00Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

---

### Retry Webhook Delivery

**POST** `/api/v1/webhooks/{webhookId}/deliveries/{deliveryId}/retry`

Retry a failed webhook delivery.

**Response (202):**
```json
{
  "deliveryId": "ulid-string",
  "status": "queued"
}
```

---

## Webhook Event Schema

All webhook payloads follow this structure:

```json
{
  "event": "order.created",
  "timestamp": "2026-05-16T10:00:00Z",
  "data": {
    "orderId": "ulid-string",
    "amount": 100.00,
    "currency": "USD"
  },
  "webhookId": "ulid-string",
  "deliveryId": "ulid-string"
}
```

### Event Types

| Category | Events |
|----------|--------|
| Orders | order.created, order.updated, order.completed, order.cancelled |
| Payments | payment.completed, payment.failed, payment.refunded |
| Users | user.created, user.updated, user.deleted |
| Sessions | session.created, session.expired, session.revoked |

---

## Security

- **Signature Verification**: All webhooks include `X-Webhook-Signature` header
- **Secret Rotation**: Secrets can be rotated without downtime
- **IP Whitelisting**: Optional IP-based access control
- **TLS Enforcement**: HTTPS required for webhook URLs

---

## Rate Limits

- Create webhooks: 10 requests/minute
- List deliveries: 30 requests/minute
- Retry delivery: 20 requests/minute