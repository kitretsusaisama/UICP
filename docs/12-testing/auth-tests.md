# Auth Tests

## Metadata
```yaml
title: Auth Tests
domain: authentication
owner: Security Team
criticality: CRITICAL
runtime-impact: LOW
security-impact: CRITICAL
queue-impact: MEDIUM
provider-impact: NONE
tenant-impact: MEDIUM
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - src/application/commands/login
  - src/application/services/auth.service.ts
  - src/infrastructure/auth/jwt-strategy.ts
related-docs:
  - docs/03-architecture/auth-flow.md
  - docs/07-security/authentication.md
related-queues: NONE
related-services:
  - AuthService
  - JwtStrategy
  - TokenRepository
```

---

## Overview

Auth tests validate all authentication flows including password-based login, OTP verification, token issuance, session management, and API key authentication. These tests are CRITICAL as they directly impact system security and tenant access.

---

## Test Coverage

### Password Authentication Flow

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Valid credentials | POST /auth/login with correct username/password | JWT token returned, session created |
| Invalid password | POST /auth/login with wrong password | 401 Unauthorized, no token |
| Non-existent user | POST /auth/login with unknown username | 401 Unauthorized |
| SQL injection attempt | POST /auth/login with "' OR '1'='1" | 400 Bad Request, input sanitized |

### OTP Authentication Flow

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Valid OTP | POST /auth/verify-otp with correct 6-digit code | Authentication succeeds |
| Expired OTP | POST /auth/verify-otp after 5-minute window | 401 Unauthorized |
| Invalid OTP | POST /auth/verify-otp with wrong digits | 401 Unauthorized |
| Rate limiting | POST /auth/verify-otp 10 times in 1 minute | 429 Too Many Requests |

### Token Management

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Valid JWT | Request with valid Bearer token | 200 OK, user context extracted |
| Expired JWT | Request with expired token | 401 Unauthorized |
| Malformed JWT | Request with invalid token format | 401 Unauthorized |
| Token refresh | POST /auth/refresh with valid refresh token | New JWT pair returned |

### API Key Authentication

| Scenario | Test Case | Expected Result |
|----------|-----------|-----------------|
| Valid primary key | X-API-Key header with valid key | Authentication succeeds |
| Valid secondary key | X-API-Key-Secondary header with valid key | Authentication succeeds |
| Revoked key | X-API-Key with deleted key | 401 Unauthorized |
| Key scope validation | Request with key lacking required scope | 403 Forbidden |

---

## Test Implementation

```typescript
describe('Authentication', () => {
  describe('Password Login', () => {
    it('should return JWT on valid credentials', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({ username: 'testuser', password: 'SecurePass123!' });

      expect(response.status).toBe(200);
      expect(response.body.token).toBeDefined();
      expect(response.body.refreshToken).toBeDefined();
    });

    it('should reject invalid password', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({ username: 'testuser', password: 'WrongPassword' });

      expect(response.status).toBe(401);
    });
  });

  describe('API Key Authentication', () => {
    it('should authenticate with valid primary API key', async () => {
      const response = await request(app)
        .get('/api/v1/providers')
        .set('X-API-Key', validApiKey);

      expect(response.status).toBe(200);
    });

    it('should reject revoked API key', async () => {
      const response = await request(app)
        .get('/api/v1/providers')
        .set('X-API-Key', revokedApiKey);

      expect(response.status).toBe(401);
    });
  });
});
```

---

## Security Considerations

All auth tests must run in isolated environments with no real tenant data. Test credentials should be rotated monthly. Failed authentication attempts should be logged with tenant ID (anonymized) for security monitoring.