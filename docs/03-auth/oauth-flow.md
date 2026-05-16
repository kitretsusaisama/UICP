# OAuth Flow

## Metadata
```yaml
title: OAuth 2.0 Authentication Flow
domain: authentication
owner: identity-team
criticality: HIGH
runtime-impact: MEDIUM
security-impact: HIGH
queue-impact: LOW
provider-impact: MEDIUM
tenant-impact: TENANT_ISOLATED
ai-ingestable: true
review-cycle: monthly
last-reviewed: 2026-05-16
depends-on:
  - auth-overview.md
  - login-flow.md
  - session-management.md
related-docs:
  - signup-flow.md
  - org-model.md
  - auth-security.md
related-queues:
  - oauth-events
  - identity-linked
related-services:
  - OAuthService
  - IdentityProvider
  - SessionService
related-runtime-states:
  - OAUTH_INITIATED
  - OAUTH_AUTHORIZED
  - OAUTH_LINKED
  - OAUTH_ERROR
```

---

## Supported Providers

UICP supports OAuth 2.0 authorization code flow with the following providers:

| Provider | Scopes | Token Type |
|----------|--------|------------|
| Google | email, profile | JWT |
| GitHub | user:email, read:user | Opaque |
| Microsoft | openid, email, profile | JWT |
| Generic OIDC | openid, profile, email | JWT |

---

## Authorization Code Flow

### Step 1: Authorization Request

Client initiates OAuth flow via `GET /v1/auth/oauth/authorize` with provider identifier, redirect URI, and requested scopes. The server generates cryptographic state parameter stored in session.

```
Authorization URL:
https://auth.uicp.internal/oauth/authorize
  ?provider=google
  &redirect_uri=https://app.uicp.internal/callback
  &scope=email%20profile
  &state=csrf-token-xyz
```

### Step 2: Provider Redirect

User authenticates with identity provider and authorizes UICP access. Provider redirects back to registered callback URL with authorization code and state parameter.

### Step 3: Token Exchange

The backend exchanges authorization code for access token and optionally ID token. The exchange validates redirect URI matches original request.

```typescript
async function exchangeCode(code: string, redirectUri: string): Promise<TokenResponse> {
  const response = await this.oauthClient.exchangeCode({
    code,
    redirectUri,
    clientId: this.config.clientId,
    clientSecret: this.config.clientSecret
  });

  return {
    accessToken: response.access_token,
    idToken: response.id_token,
    expiresIn: response.expires_in,
    refreshToken: response.refresh_token
  };
}
```

### Step 4: User Provisioning

The system extracts user identity from ID token or userinfo endpoint. If email matches existing local account, the OAuth identity links to that account. Otherwise, a new account creates with OAuth identity as primary.

---

## Token Management

### Access Token Storage

OAuth access tokens store encrypted in Redis, associated with session. Tokens refresh automatically before expiration using refresh token.

### Scope Enforcement

Issued tokens include scopes approved during authorization. The token validation layer enforces scope matching: requested scopes must be subset of authorized scopes.

---

## Security Controls

### State Parameter Validation

The OAuth state parameter prevents CSRF attacks. State validates against session-stored value; mismatches reject authorization.

### PKCE (Proof Key for Code Exchange)

For public clients (SPAs, mobile apps), PKCE extension secures authorization code flow. Code challenge derives from cryptographically random code verifier.

```typescript
// PKCE flow
const codeVerifier = generateRandomString(128);
const codeChallenge = sha256Base64(codeVerifier);

// Authorization request includes code_challenge
// Token exchange includes code_verifier
```

### Redirect URI Validation

Only pre-registered redirect URIs allow for OAuth callbacks. Dynamic redirect URIs reject to prevent authorization code interception.

---

## Related Documents

- `signup-flow.md` - Account creation via OAuth
- `org-model.md` - Tenant association
- `auth-security.md` - Security controls