# UICP - Universal Identity & Communication Platform

A domain-aware, API-key-centric multi-tenant identity and communication platform built with NestJS.

## 🎯 Architecture

**Design Pattern:** Auth0 / Clerk / Firebase style - tenant context derived from credentials, not headers.

```
Request → UnifiedAuthGuard
           ↓
    Validate credential (API Key / JWT / Session)
           ↓
    Extract tenantId from credential
           ↓
    Set req.tenantId, req.apiKey
           ↓
    Controller accesses via getTenantIdOrThrow(req)
```

## 🔑 API Key System

### Key Formats (ULID-based)

| Type | Prefix | Format | Environment |
|------|--------|--------|--------------|
| Live Publishable | `uF` | `uF{ULID26}xl` | Production client-side |
| Live Secret | `sF` | `sF{ULID26}xl{HMAC44}` | Production server-side |
| Dev Publishable | `pB` | `pB{ULID26}` | Development |
| Dev Secret | `tB` | `tB{ULID26}{HMAC44}` | Development |

### Authentication Methods

```http
Authorization: Bearer <token>
```

Token can be:
- **API Key** (uF/pB/sF/tB prefix)
- **JWT** (Bearer token)
- **Session Token** (X-Session-Token header)
- **Internal Service** (X-Internal-Service-Token header)

## 🚀 Getting Started

### Prerequisites

- Node.js 18+
- MySQL 8.0+
- Redis 6.0+

### Installation

```bash
# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# Generate required secrets
openssl rand -hex 32  # For API_KEY_HMAC_SECRET
openssl rand -hex 32  # For JWT_SECRET
openssl rand -hex 32  # For ENCRYPTION_MASTER_KEY

# Run database migrations
npm run migration:run

# Start development server
npm run start:dev
```

### Required Environment Variables

```env
# Required - API Key HMAC (min 32 chars)
API_KEY_HMAC_SECRET=your_64_char_hex_value

# Required - JWT
JWT_SECRET=your_32_char_hex_value
JWT_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n...

# Required - Database
DB_HOST=localhost
DB_PORT=3306
DB_NAME=uicp
DB_USER=uicp_user
DB_PASSWORD=your_password

# Required - Redis
REDIS_HOST=localhost
REDIS_PORT=6379
```

## 📡 API Endpoints

### Public Endpoints

```http
POST /v1/auth/signup     # Create tenant account
POST /v1/auth/login      # Authenticate
POST /v1/auth/refresh    # Refresh token
```

### Authenticated Endpoints (Tenant-Scoped)

*No X-Tenant-ID header required - tenant derived from credential*

```http
GET    /v1/users/me                  # Get current user
PATCH  /v1/users/me                  # Update user
GET    /v1/users/me/sessions          # List sessions
DELETE /v1/users/me/sessions/:id      # Revoke session
GET    /v1/users/me/identities         # List identities
GET    /v1/users/me/permissions       # Get permissions
GET    /v1/users/me/audit-logs         # Get audit logs
GET    /v1/users/me/devices            # List devices

GET    /v1/modules/:key/resources/:key  # Get module resource
POST   /v1/modules/:key/commands/:key  # Execute command
POST   /v1/modules/:key/actions/:key    # Execute action

GET    /v1/api-keys           # List API keys
POST   /v1/api-keys           # Create API key
DELETE /v1/api-keys/:id       # Revoke API key
POST   /v1/api-keys/:id/rotate # Rotate key

GET    /v1/policies           # List policies
POST   /v1/policies           # Create policy
DELETE /v1/policies/:id       # Delete policy

GET    /v1/roles              # List roles
POST   /v1/roles              # Create role
```

### Platform APIs (Admin)

```http
POST   /platform/v1/impersonate/sessions      # Start impersonation
DELETE /platform/v1/impersonate/sessions/:id  # End impersonation
GET    /platform/v1/impersonate/sessions      # List sessions
```

## 🏗️ Project Structure

```
src/
├── application/           # Application services, commands, queries
│   ├── commands/         # Write operations
│   ├── queries/          # Read operations
│   ├── services/         # Business logic
│   └── ports/            # Interfaces (driven/driving)
├── domain/               # Domain entities, value objects, repositories
│   ├── entities/         # Domain models
│   ├── value-objects/    # Immutable value types
│   └── repositories/     # Repository interfaces
├── infrastructure/        # External integrations
│   ├── db/              # MySQL repositories
│   ├── cache/            # Redis adapters
│   ├── email/            # Email providers
│   ├── queue/            # BullMQ queues
│   └── providers/        # SMS/Email providers
└── interface/
    └── http/
        ├── controllers/  # REST endpoints
        ├── guards/        # Authentication
        ├── interceptors/ # Request/response transform
        ├── pipes/         # Validation
        └── tenant/        # Tenant resolution
```

## 🔒 Security Features

- **API Key Validation**: ULID-based keys with HMAC signatures
- **IP Allowlist**: Per-key IP restrictions (CIDR support)
- **Rate Limiting**: Configurable per-key limits
- **Monthly Quotas**: Usage tracking per key
- **Key Rotation**: Automated rotation with previous key tracking
- **Emergency Revocation**: Instant key revocation capability

## 📊 Observability

- OpenTelemetry tracing support
- Structured logging
- Request correlation IDs
- Provider health monitoring

## 🧪 Testing

```bash
# Run unit tests
npm run test

# Run e2e tests
npm run test:e2e

# Run with coverage
npm run test:cov
```

## 📝 License

Private - All rights reserved