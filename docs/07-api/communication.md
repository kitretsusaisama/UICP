# Communication API

## Metadata
```yaml
title: Communication API
domain: api
owner: communication-team
criticality: HIGH
runtime-impact: medium
security-impact: MEDIUM
queue-impact: high
provider-impact: high
tenant-impact: isolated
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - authentication.md
  - providers.md
related-docs:
  - providers.md
  - webhooks.md
related-queues:
  - email-outbound
  - sms-outbound
  - notification-outbound
related-services:
  - EmailProvider
  - NotificationService
  - QueueAdapter
```

---

## Overview

The Communication API provides endpoints for sending emails, SMS messages, and push notifications. All communications are processed asynchronously via queues and support templating, tracking, and delivery status callbacks.

---

## Endpoints

### Send Email

**POST** `/api/v1/communications/email`

Send an email message.

**Request:**
```json
{
  "to": ["recipient@example.com"],
  "cc": ["cc@example.com"],
  "bcc": ["bcc@example.com"],
  "from": "noreply@company.com",
  "subject": "Welcome to Our Platform",
  "templateId": "tmpl-welcome-001",
  "templateData": {
    "name": "John",
    "verificationUrl": "https://..."
  },
  "attachments": [
    {
      "filename": "invoice.pdf",
      "content": "base64-encoded..."
    }
  ],
  "metadata": {
    "campaignId": "campaign-123"
  }
}
```

**Response (202):**
```json
{
  "messageId": "msg-ulid-001",
  "status": "queued",
  "queuedAt": "2026-05-16T10:00:00Z"
}
```

---

### Send SMS

**POST** `/api/v1/communications/sms`

Send an SMS message.

**Request:**
```json
{
  "to": "+1234567890",
  "message": "Your verification code is 123456",
  "templateId": "tmpl-verify-sms",
  "templateData": {
    "code": "123456"
  },
  "metadata": {
    "userId": "ulid-string"
  }
}
```

**Response (202):**
```json
{
  "messageId": "msg-ulid-002",
  "status": "queued"
}
```

---

### Send Push Notification

**POST** `/api/v1/communications/push`

Send a push notification to devices.

**Request:**
```json
{
  "userId": "ulid-string",
  "title": "New Message",
  "body": "You have a new message",
  "data": {
    "type": "message",
    "messageId": "msg-123"
  },
  "priority": "high",
  "ttl": 3600
}
```

**Response (202):** Message queued

---

### Get Message Status

**GET** `/api/v1/communications/{messageId}`

Retrieve delivery status of a sent message.

**Response (200):**
```json
{
  "messageId": "msg-ulid-001",
  "status": "delivered",
  "provider": "sendgrid",
  "providerMessageId": "sg-abc123",
  "deliveredAt": "2026-05-16T10:01:00Z",
  "events": [
    {
      "event": "sent",
      "timestamp": "2026-05-16T10:00:30Z"
    },
    {
      "event": "delivered",
      "timestamp": "2026-05-16T10:01:00Z"
    }
  ]
}
```

---

### List Messages

**GET** `/api/v1/communications`

List communication messages with filters.

**Query Parameters:**
- `type` (string: email, sms, push)
- `status` (string: queued, sent, delivered, failed)
- `limit` (integer, default: 20, max: 100)
- `offset` (integer, default: 0)

**Response (200):**
```json
{
  "messages": [
    {
      "messageId": "msg-ulid-001",
      "type": "email",
      "status": "delivered",
      "to": "recipient@example.com",
      "createdAt": "2026-05-16T10:00:00Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

---

### Create Email Template

**POST** `/api/v1/communications/templates`

Create a reusable email template.

**Request:**
```json
{
  "name": "Welcome Email",
  "type": "email",
  "subject": "Welcome {{name}}!",
  "htmlBody": "<h1>Hello {{name}}</h1><p>...</p>",
  "textBody": "Hello {{name}}, ...",
  "variables": ["name", "verificationUrl"]
}
```

**Response (201):** Template created

---

## Message Data Model

| Field | Type | Description |
|-------|------|-------------|
| messageId | ULID | Unique message identifier |
| type | enum | email, sms, push |
| status | enum | queued, sent, delivered, failed, bounced |
| to | array/string | Recipients |
| from | string | Sender address |
| subject | string | Email subject |
| templateId | string | Associated template |
| provider | string | Provider name used |
| providerMessageId | string | Provider's message ID |
| metadata | object | Custom context |
| createdAt | ISO8601 | Creation timestamp |
| deliveredAt | ISO8601 | Delivery timestamp |

---

## Rate Limits

- Send email: 100 requests/minute per tenant
- Send SMS: 50 requests/minute per tenant
- Send push: 100 requests/minute per tenant
- Get status: 60 requests/minute