# Frontend Analysis (Next.js)

**Analysis Date:** 2026-05-16

---

## 1. Frontend Architecture

### 1.1 Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | Next.js (App Router) |
| Language | TypeScript |
| UI Framework | React |
| Styling | Tailwind CSS |
| State | Zustand |

---

## 2. Directory Structure

```
apps/web/
├── app/                    # Next.js App Router
│   ├── auth/              # Authentication pages
│   ├── dashboard/         # Protected dashboard
│   └── health/            # Health check
├── components/            # Reusable components
│   ├── AppShell.tsx
│   └── otp/              # OTP widget
├── services/             # API client services
├── stores/               # Zustand stores
└── lib/                  # Utilities
```

---

## 3. Authentication Flow

### 3.1 Login Flow
1. User enters credentials on /auth/login
2. POST to /v1/auth/attempt
3. Receive accessToken + refreshToken
4. Store in auth.store.ts
5. Redirect to /dashboard/overview

### 3.2 OAuth Flow
1. User clicks OAuth provider
2. Redirect to /auth/oauth/callback
3. Handle OAuth callback
4. Exchange code for tokens

---

## 4. API Client

### 4.1 Service Layer

| Service | Purpose |
|---------|---------|
| auth.service.ts | Login, register, OAuth |
| user.service.ts | User CRUD |
| session.service.ts | Session management |
| provider.service.ts | Provider health |
| audit.service.ts | Audit logs |
| queue.service.ts | Queue monitoring |
| security.service.ts | Security alerts |

---

## 5. State Management

### 5.1 Stores (Zustand)

- auth.store.ts - Authentication state
- tenant.store.ts - Tenant selection
- notification.store.ts - Notifications

---

## 6. Pages

### 6.1 Auth Pages
- /auth/login
- /auth/register
- /auth/forgot-password
- /auth/verify-otp
- /auth/oauth/callback

### 6.2 Dashboard Pages
- /dashboard/overview
- /dashboard/users
- /dashboard/sessions
- /dashboard/providers
- /dashboard/security
- /dashboard/analytics
- /dashboard/audit
- /dashboard/tenants
- /dashboard/queues
- /dashboard/developer

---

## 7. Security Gaps

| Issue | Impact |
|-------|--------|
| Tokens in memory only | Lost on page refresh |
| No logout on unload | Session may persist |
| No session expiry handling | Could show stale data |

---

## 8. Conclusion

The frontend is a **well-structured Next.js application** with:
- Clean App Router structure
- Proper authentication flow
- Zustand for state management

**Primary Gaps:**
1. Token storage only in memory
2. No React Query for data caching
3. Limited loading/error states