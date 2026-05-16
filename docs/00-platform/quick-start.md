# UICP Quick Start Guide

## Metadata

```yaml
title: UICP Quick Start Guide
domain: onboarding
owner: Developer Relations
criticality: MEDIUM
runtime-impact: LOW
security-impact: MEDIUM
queue-impact: LOW
provider-impact: LOW
tenant-impact: LOW
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - architecture-summary.md
  - terminology.md
related-docs:
  - engineering-principles.md
  - platform-philosophy.md
  - operational-thinking.md
related-queues:
  - otp-fastlane
  - email-delivery
related-services:
  - api-gateway
  - auth-service
  - tenant-service
  - communication-service
related-providers:
  - sendgrid
  - twilio
related-runtime-states:
  - starting
  - running
related-threat-models: []
```

---

## Prerequisites

- Node.js 18+ installed
- MySQL 8.0+ running
- Redis 6.0+ running
- npm or yarn package manager

---

## Step 1: Local Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/your-org/uicp.git
cd uicp
npm install
```

Copy the environment template:

```bash
cp .env.example .env
```

Configure your local environment:

```bash
# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=uicp

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Application
APP_PORT=3000
JWT_SECRET=your-development-secret
ENCRYPTION_KEY=your-32-byte-hex-key
```

---

## Step 2: Database Setup

Run migrations to create the schema:

```bash
npm run migration:run
```

Verify tables created:
- `api_keys` — API key storage
- `tenants` — Multi-tenant data
- `users` — User accounts
- `sessions` — Active sessions
- `audit_logs` — Immutable audit trail

---

## Step 3: Start the Application

```bash
npm run start:dev
```

The API should be available at `http://localhost:3000`

---

## Step 4: Create Your First Tenant

Using curl:

```bash
curl -X POST http://localhost:3000/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp",
    "domain": "acme.example.com",
    "plan": "enterprise"
  }'
```

Response:

```json
{
  "data": {
    "tenantId": "01ARZ3NDEKTSV4RRFFQ69G1FAV",
    "name": "Acme Corp",
    "domain": "acme.example.com",
    "plan": "enterprise",
    "createdAt": "2026-05-16T10:30:00Z"
  }
}
```

---

## Step 5: Generate API Keys

Create an API key pair for your tenant:

```bash
curl -X POST http://localhost:3000/v1/api-keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-jwt>" \
  -d '{
    "tenantId": "01ARZ3NDEKTSV4RRFFQ69G1FAV",
    "name": "Production Key",
    "permissions": ["read", "write", "communication"]
  }'
```

Response:

```json
{
  "data": {
    "publishableKey": "uF01ARZ3NDEKTSV4RRFFQ69G1FAV",
    "secretKey": "sF01ARZ3NDEKTSV4RRFFQ69G1FAV",
    "keyId": "01ARZ3NDEKTSV4RRFFQ69G1FAY",
    "name": "Production Key",
    "createdAt": "2026-05-16T10:30:00Z"
  }
}
```

**Important**: Save the secret key securely. It is shown only once.

---

## Step 6: Make Your First Authenticated Request

Use the publishable key to authenticate:

```bash
curl http://localhost:3000/v1/users/me \
  -H "Authorization: Bearer uF01ARZ3NDEKTSV4RRFFQ69G1FAV"
```

The system resolves the tenant from the key prefix (`uF` = publishable).

---

## Step 7: Send a Test Email

Queue an email for delivery:

```bash
curl -X POST http://localhost:3000/v1/communication/email/send \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sF01ARZ3NDEKTSV4RRFFQ69G1FAV" \
  -d '{
    "to": "user@example.com",
    "from": "noreply@acme.example.com",
    "subject": "Welcome to UICP",
    "body": "Hello! This is a test email.",
    "idempotencyKey": "01ARZ3NDEKTSV4RRFFQ69G1FAZ"
  }'
```

Response (immediate):

```json
{
  "data": {
    "jobId": "01ARZ3NDEKTSV4RRFFQ69G1FAV",
    "status": "queued",
    "idempotencyKey": "01ARZ3NDEKTSV4RRFFQ69G1FAZ"
  }
}
```

The email is processed asynchronously via BullMQ.

---

## Key Concepts

### API Key Prefix Types
| Prefix | Type | Use Case |
|--------|------|----------|
| `uF` | Publishable | Client-side, read-only |
| `sF` | Secret | Server-side, full access |
| `pB` | Public | Public API operations |
| `tB` | Test | Development/sandbox |

### Queue-First Architecture
All external operations are async. Use the returned `jobId` to check status.

### Idempotency
Every mutation requires an idempotency key (ULID). This prevents duplicate processing.

---

## Common Tasks

### Check API Key Permissions

```bash
curl http://localhost:3000/v1/api-keys/verify \
  -H "Authorization: Bearer sF01ARZ3NDEKTSV4RRFFQ69G1FAV"
```

### View Tenant Audit Logs

```bash
curl http://localhost:3000/v1/audit/logs \
  -H "Authorization: Bearer sF01ARZ3NDEKTSV4RRFFQ69G1FAV" \
  -H "X-Tenant-ID: 01ARZ3NDEKTSV4RRFFQ69G1FAV"
```

### Send OTP

```bash
curl -X POST http://localhost:3000/v1/auth/otp/send \
  -H "Authorization: Bearer sF01ARZ3NDEKTSV4RRFFQ69G1FAV" \
  -d '{
    "phone": "+1234567890",
    "tenantId": "01ARZ3NDEKTSV4RRFFQ69G1FAV"
  }'
```

---

## Next Steps

1. **Read the Architecture Summary** — Understand the system design
2. **Review Engineering Principles** — Learn the code standards
3. **Explore the API Reference** — Full endpoint documentation
4. **Set Up Monitoring** — Configure Grafana dashboards
5. **Join the Community** — Slack channel for questions

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection refused | Check MySQL/Redis are running |
| 401 Unauthorized | Verify API key is valid and not revoked |
| 429 Too Many Requests | Implement rate limiting |
| Email not sent | Check queue worker logs |
| Slow response | Check database query performance |

---

*Last Updated: 2026-05-16 | AI-Ingestible: true*