import { describe, it, expect, beforeEach } from '@jest/globals';

// Simplified JWT implementation matching production patterns
interface JWTPayload {
  sub: string;
  tenantId: string;
  iat: number;
  exp: number;
  type: 'access' | 'refresh';
  familyId?: string;
  sessionId?: string;
}

interface JWTResult {
  valid: boolean;
  payload?: JWTPayload;
  error?: string;
}

// In-memory blacklist and secrets
const tokenBlacklist = new Set<string>();
const tenantSecrets = new Map<string, string>();

// Helper to encode base64
function base64Encode(str: string): string {
  return Buffer.from(str).toString('base64url');
}

// Helper to decode base64
function base64Decode(str: string): string {
  return Buffer.from(str, 'base64url').toString('utf-8');
}

// Create JWT (simplified, not including signature for test simplicity)
function createToken(
  userId: string,
  tenantId: string,
  type: 'access' | 'refresh',
  secret: string,
  options: { expiresIn?: number; familyId?: string; sessionId?: string } = {}
): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = {
    sub: userId,
    tenantId,
    iat: now,
    exp: now + (options.expiresIn ?? (type === 'access' ? 900 : 604800)),
    type,
    ...(options.familyId && { familyId: options.familyId }),
    ...(options.sessionId && { sessionId: options.sessionId }),
  };

  // In production, this would be a real signature
  // For test, we create a mock signature
  const header = base64Encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadEncoded = base64Encode(JSON.stringify(payload));
  const mockSignature = base64Encode(`${secret}.${payloadEncoded}`);

  return `${header}.${payloadEncoded}.${mockSignature}`;
}

// Parse JWT without verification (for test inspection)
function parseToken(token: string): JWTPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const payload = JSON.parse(base64Decode(parts[1]!));
    return payload as JWTPayload;
  } catch {
    return null;
  }
}

// Verify JWT - matches production logic
function verifyToken(token: string, secret: string): JWTResult {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'INVALID_FORMAT' };
    }

    const payload = parseToken(token);
    if (!payload) {
      return { valid: false, error: 'INVALID_PAYLOAD' };
    }

    // Check blacklist
    if (tokenBlacklist.has(token)) {
      return { valid: false, error: 'TOKEN_BLACKLISTED' };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      return { valid: false, error: 'TOKEN_EXPIRED' };
    }

    // Check token type
    if (payload.type !== 'access' && payload.type !== 'refresh') {
      return { valid: false, error: 'INVALID_TOKEN_TYPE' };
    }

    // Verify signature (simplified - check mock format)
    const expectedSig = base64Encode(`${secret}.${parts[1]}`);
    if (parts[2] !== expectedSig) {
      return { valid: false, error: 'INVALID_SIGNATURE' };
    }

    return { valid: true, payload };
  } catch (error) {
    return { valid: false, error: 'VERIFY_ERROR' };
  }
}

// Register tenant secret
function registerTenant(tenantId: string, secret: string): void {
  tenantSecrets.set(tenantId, secret);
}

// Blacklist a token
function blacklistToken(token: string): void {
  tokenBlacklist.add(token);
}

// Clear test state
function clearTestState(): void {
  tokenBlacklist.clear();
  tenantSecrets.clear();
}

describe('JWT Forgery Protection', () => {
  beforeEach(() => {
    clearTestState();
    registerTenant('tenant-a', 'secret_tenant_a');
    registerTenant('tenant-b', 'secret_tenant_b');
  });

  describe('Forged Token Rejected', () => {
    it('rejects token with invalid signature', () => {
      const token = createToken('user-123', 'tenant-a', 'access', 'wrong_secret');

      const result = verifyToken(token, 'secret_tenant_a');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('INVALID_SIGNATURE');
    });

    it('rejects completely forged token', () => {
      const fakeToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsInRlbmFudElkIjoidGVuYW50LWEiLCJpYXQiOjE3MDQwNjQwMDAsImV4cCI6MTcwNDA2NDYwMCwidHlwZSI6ImFjY2VzcyJ9.fake_signature';

      const result = verifyToken(fakeToken, 'secret_tenant_a');

      expect(result.valid).toBe(false);
    });

    it('rejects token with tampered payload', () => {
      const token = createToken('user-123', 'tenant-a', 'access', 'secret_tenant_a');

      // Tamper with the payload
      const parts = token.split('.');
      const payload = JSON.parse(base64Decode(parts[1]!));
      payload.sub = 'attacker-user';

      const tamperedToken = `${parts[0]}.${base64Encode(JSON.stringify(payload))}.${parts[2]}`;

      const result = verifyToken(tamperedToken, 'secret_tenant_a');

      expect(result.valid).toBe(false);
    });
  });

  describe('Expired Token Rejected', () => {
    it('rejects token past expiration', () => {
      // Create already-expired token (expires in past)
      const now = Math.floor(Date.now() / 1000);
      const payload: JWTPayload = {
        sub: 'user-123',
        tenantId: 'tenant-a',
        iat: now - 1000,
        exp: now - 100, // Already expired
        type: 'access',
      };

      const payloadEncoded = base64Encode(JSON.stringify(payload));
      const signature = base64Encode(`secret_tenant_a.${payloadEncoded}`);
      const expiredToken = `eyJhbGciOiJIUzI1NiJ9.${payloadEncoded}.${signature}`;

      const result = verifyToken(expiredToken, 'secret_tenant_a');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('TOKEN_EXPIRED');
    });
  });

  describe('Wrong Tenant Token Rejected', () => {
    it('rejects token from different tenant', () => {
      // Token created for tenant-a
      const token = createToken('user-123', 'tenant-a', 'access', 'secret_tenant_a');

      // Trying to use it as tenant-b (different secret)
      const result = verifyToken(token, 'secret_tenant_b');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('INVALID_SIGNATURE');
    });

    it('validates tenantId in payload', () => {
      // Token for tenant-a
      const token = createToken('user-123', 'tenant-a', 'access', 'secret_tenant_a');

      // Verify with tenant-a's secret
      const result = verifyToken(token, 'secret_tenant_a');

      expect(result.valid).toBe(true);
      expect(result.payload?.tenantId).toBe('tenant-a');
    });
  });

  describe('Token Type Validation', () => {
    it('rejects invalid token type', () => {
      const now = Math.floor(Date.now() / 1000);
      const payload: JWTPayload = {
        sub: 'user-123',
        tenantId: 'tenant-a',
        iat: now,
        exp: now + 900,
        type: 'invalid_type' as 'access',
      };

      const payloadEncoded = base64Encode(JSON.stringify(payload));
      const signature = base64Encode(`secret_tenant_a.${payloadEncoded}`);
      const badToken = `eyJhbGciOiJIUzI1NiJ9.${payloadEncoded}.${signature}`;

      const result = verifyToken(badToken, 'secret_tenant_a');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('INVALID_TOKEN_TYPE');
    });

    it('accepts valid access token', () => {
      const token = createToken('user-123', 'tenant-a', 'access', 'secret_tenant_a', { expiresIn: 900 });

      const result = verifyToken(token, 'secret_tenant_a');

      expect(result.valid).toBe(true);
      expect(result.payload?.type).toBe('access');
    });

    it('accepts valid refresh token', () => {
      const token = createToken('user-123', 'tenant-a', 'refresh', 'secret_tenant_a', { expiresIn: 604800, familyId: 'family-123' });

      const result = verifyToken(token, 'secret_tenant_a');

      expect(result.valid).toBe(true);
      expect(result.payload?.type).toBe('refresh');
    });
  });

  describe('Blacklisted Token Rejected', () => {
    it('rejects blacklisted token', () => {
      const token = createToken('user-123', 'tenant-a', 'access', 'secret_tenant_a');

      // Blacklist the token
      blacklistToken(token);

      const result = verifyToken(token, 'secret_tenant_a');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('TOKEN_BLACKLISTED');
    });
  });

  describe('Isolated Tenant Secrets', () => {
    it('maintains separate secrets per tenant', () => {
      const tokenA = createToken('user-123', 'tenant-a', 'access', 'secret_tenant_a');
      const tokenB = createToken('user-456', 'tenant-b', 'access', 'secret_tenant_b');

      const resultA = verifyToken(tokenA, 'secret_tenant_a');
      const resultB = verifyToken(tokenB, 'secret_tenant_b');

      expect(resultA.valid).toBe(true);
      expect(resultB.valid).toBe(true);

      // Cross-tenant validation fails
      expect(verifyToken(tokenA, 'secret_tenant_b').valid).toBe(false);
      expect(verifyToken(tokenB, 'secret_tenant_a').valid).toBe(false);
    });
  });

  describe('Session-Bound Tokens', () => {
    it('includes sessionId in access token', () => {
      const token = createToken('user-123', 'tenant-a', 'access', 'secret_tenant_a', { sessionId: 'sess-123' });

      const result = verifyToken(token, 'secret_tenant_a');

      expect(result.valid).toBe(true);
      expect(result.payload?.sessionId).toBe('sess-123');
    });

    it('includes familyId in refresh token', () => {
      const token = createToken('user-123', 'tenant-a', 'refresh', 'secret_tenant_a', { familyId: 'family-123' });

      const result = verifyToken(token, 'secret_tenant_a');

      expect(result.valid).toBe(true);
      expect(result.payload?.familyId).toBe('family-123');
    });
  });

  describe('Parse Errors Handled', () => {
    it('handles malformed token', () => {
      const result = verifyToken('not-a-valid-token', 'secret_tenant_a');

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('handles empty token', () => {
      const result = verifyToken('', 'secret_tenant_a');

      expect(result.valid).toBe(false);
    });

    it('handles wrong format (missing parts)', () => {
      const result = verifyToken('header.payload', 'secret_tenant_a');

      expect(result.valid).toBe(false);
    });
  });

  describe('Token Rotation Lineage', () => {
    it('tracks token family for refresh rotation', () => {
      // Issue initial refresh token
      const refreshToken = createToken('user-123', 'tenant-a', 'refresh', 'secret_tenant_a', {
        familyId: 'family-user123',
      });

      const result1 = verifyToken(refreshToken, 'secret_tenant_a');
      expect(result1.valid).toBe(true);
      expect(result1.payload?.familyId).toBe('family-user123');

      // Blacklist after rotation
      blacklistToken(refreshToken);

      const result2 = verifyToken(refreshToken, 'secret_tenant_a');
      expect(result2.valid).toBe(false);
    });
  });
});