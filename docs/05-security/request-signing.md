# Request Signing

## Metadata
```yaml
title: Request Signing
domain: security
owner: Security Team
criticality: CRITICAL
runtime-impact: HIGH
security-impact: CRITICAL
queue-impact: NONE
provider-impact: NONE
tenant-impact: HIGH
ai-ingestable: true
review-cycle: quarterly
last-reviewed: 2026-05-16
depends-on:
  - 05-security/api-key-security.md
  - 05-security/hmac-validation.md
  - 05-security/replay-protection.md
related-docs:
  - 05-security/zero-trust-model.md
  - 05-security/nonce-model.md
related-queues: []
related-services:
  - RequestSigner
  - SignatureValidator
  - UnifiedAuthGuard
related-runtime-states:
  - unsigned
  - signed
  - signature-invalid
```

---

## Executive Summary

Request signing ensures request integrity and authenticity. All API key authenticated requests must include a valid HMAC-SHA256 signature that is validated on every request.

---

## Signing Algorithm

### Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    SIGNATURE COMPONENTS                         │
├─────────────────────────────────────────────────────────────────┤
│  1. HTTP Method (uppercase): GET, POST, PUT, DELETE            │
│  2. Canonical Path: /v1/resources with normalized query        │
│  3. Timestamp: X-Timestamp header (Unix epoch)                │
│  4. Nonce: X-Nonce header (required for writes)                │
│  5. Body Hash: SHA-256 of request body (base64url encoded)    │
└─────────────────────────────────────────────────────────────────┘
```

### Payload Construction

```typescript
function constructSigningPayload(request: HttpRequest): string {
  const parts = [
    request.method.toUpperCase(),
    canonicalizePath(request.path),
    request.headers['x-timestamp'],
    request.headers['x-nonce'] || '',
    sha256Base64Url(request.body || '')
  ];

  return parts.join('\n');
}

// Example payload:
// POST
// /v1/queues
// 1704067200
// 01ARZ3NDEKTSV4RRFFQ69G5FAV
// PMvOI6qLJPChVfYyrGJKmJHGaJwF1N7hKxW8F3mG1M0
```

### HMAC Calculation

```typescript
function calculateSignature(payload: string, secret: string): string {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(payload);
  return hmac.digest('base64url');
}

// Final signature header:
// X-Signature: hmac-sha256=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## Request Flow

```
CLIENT                                                     SERVER
  │                                                          │
  │  1. Prepare request (method, path, body)                │
  │                                                          │
  │  2. Add required headers:                                │
  │     - X-Timestamp: 1704067200                            │
  │     - X-Nonce: 01ARZ3NDEKTSV4RRFFQ69G5FAV                │
  │     - X-API-Key: uF01ARZ3NDEKTSV4RRFFQ69G5FAV            │
  │                                                          │
  │  3. Construct signing payload                            │
  │                                                          │
  │  4. Calculate HMAC-SHA256 with API key secret            │
  │                                                          │
  │  5. Add signature header:                                │
  │     - X-Signature: hmac-sha256=<signature>               │
  │────────────────────────────────────────────────────────▶│
  │                                                          │
  │                                                  6. Extract API key ID
  │                                                          │
  │                                                  7. Lookup secret hash
  │                                                          │
  │                                                  8. Reconstruct payload
  │                                                          │
  │                                                  9. Verify HMAC
  │                                                          │
  │◀─────────────────────────────────────────────────────────│
  │     10. Return 200 OK or 401 Unauthorized                 │
  │                                                          │
```

---

## Signature Validation

```typescript
async function validateSignature(
  request: IncomingMessage,
  apiKey: ApiKey
): Promise<ValidationResult> {
  // 1. Check required headers
  const timestamp = request.headers['x-timestamp'];
  const signature = request.headers['x-signature'];

  if (!timestamp || !signature) {
    return { valid: false, reason: 'Missing required headers' };
  }

  // 2. Validate timestamp (prevent replay)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestamp)) > 300) {
    return { valid: false, reason: 'Timestamp out of range' };
  }

  // 3. Reconstruct signing payload
  const payload = constructSigningPayload(request);

  // 4. Verify HMAC using stored secret hash
  const expectedSignature = crypto
    .createHmac('sha256', apiKey.secretHash)
    .update(payload)
    .digest('base64url');

  if (!crypto.timingSafeEqual(
    Buffer.from(signature.replace('hmac-sha256=', '')),
    Buffer.from(expectedSignature)
  )) {
    return { valid: false, reason: 'Invalid signature' };
  }

  // 5. Validate nonce for write operations
  if (['POST', 'PUT', 'DELETE'].includes(request.method)) {
    const nonceValidation = await validateNonce(
      request.headers['x-nonce'],
      apiKey.tenantId,
      apiKey.id
    );
    if (!nonceValidation.valid) {
      return nonceValidation;
    }
  }

  return { valid: true };
}
```

---

## Client Implementation Examples

### cURL

```bash
# Generate signature
TIMESTAMP=$(date +%s)
NONCE=$(ulid)
BODY_HASH=$(echo '{"queue":"email"}' | openssl dgst -sha256 -binary | base64url)
PAYLOAD="POST\n/v1/queues\n${TIMESTAMP}\n${NONCE}\n${BODY_HASH}"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" -binary | base64url)

# Send request
curl -X POST https://api.uicp.dev/v1/queues \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-Nonce: $NONCE" \
  -H "X-Signature: hmac-sha256=$SIGNATURE" \
  -d '{"queue":"email"}'
```

### TypeScript

```typescript
import { createHmac } from 'crypto';

async function signedRequest(
  apiKey: string,
  secret: string,
  method: string,
  path: string,
  body?: object
) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = ulid();
  const bodyHash = body ? sha256Base64Url(JSON.stringify(body)) : '';

  const payload = [method.toUpperCase(), path, timestamp, nonce, bodyHash].join('\n');
  const signature = createHmac('sha256', secret).update(payload).digest('base64url');

  return fetch(`https://api.uicp.dev${path}`, {
    method,
    headers: {
      'X-API-Key': apiKey,
      'X-Timestamp': timestamp.toString(),
      'X-Nonce': nonce,
      'X-Signature': `hmac-sha256=${signature}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
}
```

---

## Error Handling

| Error Code | Meaning | Client Action |
|------------|---------|----------------|
| 401 Missing Headers | Required signing headers missing | Add all required headers |
| 401 Timestamp Out of Range | Clock skew too large | Sync clock, retry |
| 401 Invalid Signature | HMAC verification failed | Check secret, recompute |
| 401 Nonce Used | Request replay detected | Generate new nonce |
| 429 Rate Limited | Too many requests | Back off, respect retry-after |

---

## Trust Boundaries

| Component | Trust Level |
|-----------|------------|
| Client | UNTRUSTED - must sign all requests |
| API Gateway | BOUNDARY - validates signatures |
| Application | TRUSTED - signature already validated |

---

## Related Documents

- `05-security/api-key-security.md`
- `05-security/hmac-validation.md`
- `05-security/replay-protection.md`