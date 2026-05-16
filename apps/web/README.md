# UICP Frontend

Next.js App Router frontend for the Unified Identity & Communication Platform.

## Architecture

```
apps/web/
├── app/
│   ├── (auth)/           # Auth route group (no dashboard chrome)
│   │   ├── login/
│   │   ├── register/
│   │   ├── verify-otp/
│   │   ├── forgot-password/
│   │   └── oauth/callback/
│   ├── (dashboard)/       # Dashboard route group (shared sidebar/topbar)
│   │   └── dashboard/
│   │       ├── overview/
│   │       ├── users/
│   │       ├── sessions/
│   │       ├── providers/
│   │       ├── security/
│   │       ├── queues/
│   │       ├── audit/
│   │       ├── analytics/
│   │       ├── tenants/
│   │       ├── settings/
│   │       └── developer/
│   └── health/
├── services/             # API service layer
├── stores/               # Zustand state management
├── types/                # Shared TypeScript types
└── lib/                  # Utilities (api-client, etc.)
```

## Services

- `auth.service.ts` — Login, OTP, OAuth, token management
- `user.service.ts` — Profile, identities, permissions
- `session.service.ts` — Session list, revocation, devices
- `provider.service.ts` — Provider health, fallback chains
- `audit.service.ts` — Log querying, export, lineage
- `queue.service.ts` — BullMQ monitoring, dead letter queue
- `security.service.ts` — Threat events, brute force, incidents

## Stores (Zustand)

- `auth.store.ts` — Auth tokens, user profile, tenant context
- `tenant.store.ts` — Multi-tenant state
- `notification.store.ts` — Global notifications

## Getting Started

```bash
cd apps/web
npm install
npm run dev
```

Visit `http://localhost:3000`

## Backend Connection

The frontend connects to the NestJS backend at `http://localhost:3001`. Ensure the backend is running before testing API calls.

## Auth Flow

1. User lands on `/login` (auth layout)
2. POST `/v1/auth/login` with X-Tenant-ID header
3. On success, tokens stored + redirect to `/dashboard/overview`
4. All subsequent requests include Bearer token + X-Tenant-ID

## Key Routes

- `/login` — Email/phone + password login
- `/register` — Sign up with email or phone
- `/verify-otp` — OTP verification flow
- `/dashboard/overview` — Real-time metrics dashboard
- `/dashboard/sessions` — Session management
- `/dashboard/security` — SOC threat monitoring
- `/dashboard/providers` — Provider health + failover
- `/dashboard/queues` — BullMQ monitoring
- `/dashboard/audit` — Immutable audit trail
- `/health` — Backend health check