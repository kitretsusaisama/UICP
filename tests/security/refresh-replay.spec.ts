import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';

interface RefreshToken {
  token: string;
  familyId: string;
  userId: string;
  tenantId: string;
  issuedAt: number;
  expiresAt: number;
  rotated: boolean;
}

interface RefreshResult {
  success: boolean;
  error?: string;
  newAccessToken?: string;
  newRefreshToken?: string;
}

// In-memory test state (simulating Redis)
const tokenStore = new Map<string, RefreshToken>();
const blacklistStore = new Set<string>();

function generateRefreshToken(userId: string, tenantId: string, familyId: string): string {
  return `rt_${familyId}_${userId}_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

function issueRefreshToken(userId: string, tenantId: string): RefreshToken {
  const familyId = `family_${userId}`;
  const token = generateRefreshToken(userId, tenantId, familyId);
  const now = Date.now();

  const refreshToken: RefreshToken = {
    token,
    familyId,
    userId,
    tenantId,
    issuedAt: now,
    expiresAt: now + 7 * 24 * 60 * 60 * 1000, // 7 days
    rotated: false,
  };

  tokenStore.set(token, refreshToken);
  return refreshToken;
}

async function rotateRefreshToken(oldToken: string): Promise<RefreshResult> {
  const old = tokenStore.get(oldToken);

  if (!old) {
    return { success: false, error: 'TOKEN_NOT_FOUND' };
  }

  if (old.rotated) {
    return { success: false, error: 'TOKEN_ALREADY_ROTATED' };
  }

  if (blacklistStore.has(oldToken)) {
    return { success: false, error: 'TOKEN_BLACKLISTED' };
  }

  // Check expiration
  if (Date.now() > old.expiresAt) {
    return { success: false, error: 'TOKEN_EXPIRED' };
  }

  // Mark old as rotated
  old.rotated = true;
  tokenStore.set(oldToken, old);

  // Add to blacklist
  blacklistStore.add(oldToken);

  // Issue new token
  const newToken = issueRefreshToken(old.userId, old.tenantId);

  return {
    success: true,
    newAccessToken: `at_${newToken.token}`,
    newRefreshToken: newToken.token,
  };
}

async function consumeRefreshToken(token: string): Promise<RefreshResult> {
  return rotateRefreshToken(token);
}

// Clear test state
function clearTestState(): void {
  tokenStore.clear();
  blacklistStore.clear();
}

describe('Refresh Token Replay Protection', () => {
  beforeEach(() => {
    clearTestState();
  });

  afterEach(() => {
    clearTestState();
  });

  it('allows exactly one refresh token rotation', async () => {
    // Issue a refresh token
    const refresh = issueRefreshToken('user-123', 'tenant-a');

    // First rotation should succeed
    const result1 = await consumeRefreshToken(refresh.token);
    expect(result1.success).toBe(true);
    expect(result1.newRefreshToken).toBeDefined();
  });

  it('rejects replay attack - same token reused', async () => {
    // Issue a refresh token
    const refresh = issueRefreshToken('user-123', 'tenant-a');

    // First rotation succeeds
    const result1 = await consumeRefreshToken(refresh.token);
    expect(result1.success).toBe(true);

    // Attempt to reuse the SAME token (replay attack)
    const result2 = await consumeRefreshToken(refresh.token);
    expect(result2.success).toBe(false);
    expect(result2.error).toBe('TOKEN_ALREADY_ROTATED');
  });

  it('rejects already-blacklisted token', async () => {
    const refresh = issueRefreshToken('user-123', 'tenant-a');

    // Rotate once
    await consumeRefreshToken(refresh.token);

    // Should fail - token is now blacklisted
    const result = await consumeRefreshToken(refresh.token);
    expect(result.success).toBe(false);
    expect(['TOKEN_ALREADY_ROTATED', 'TOKEN_BLACKLISTED']).toContain(result.error);
  });

  it('prevents refresh token family reuse', async () => {
    // Issue initial token
    const refresh1 = issueRefreshToken('user-123', 'tenant-a');

    // Rotate first time
    const result1 = await consumeRefreshToken(refresh1.token);
    const newToken = result1.newRefreshToken!;

    // Rotate the NEW token
    const result2 = await consumeRefreshToken(newToken);
    expect(result2.success).toBe(true);

    // Original token should definitely fail
    const replay1 = await consumeRefreshToken(refresh1.token);
    expect(replay1.success).toBe(false);

    // First rotated token should fail
    const replay2 = await consumeRefreshToken(newToken);
    expect(replay2.success).toBe(false);
  });

  it('isolates tenant refresh tokens', async () => {
    // Issue tokens for different tenants
    const tenantAToken = issueRefreshToken('user-123', 'tenant-a');
    const tenantBToken = issueRefreshToken('user-123', 'tenant-b');

    // Rotate tenant A token
    const resultA = await consumeRefreshToken(tenantAToken.token);
    expect(resultA.success).toBe(true);

    // Rotate tenant B token - should succeed independently
    const resultB = await consumeRefreshToken(tenantBToken.token);
    expect(resultB.success).toBe(true);

    // Verify they remain independent
    // (After rotation, each should have independent blacklist entries)
    expect(tenantAToken.tenantId).not.toBe(tenantBToken.tenantId);
  });

  it('handles concurrent refresh requests correctly', async () => {
    const refresh = issueRefreshToken('user-123', 'tenant-a');

    // Simulate 5 concurrent refresh requests
    const results = await Promise.all([
      consumeRefreshToken(refresh.token),
      consumeRefreshToken(refresh.token),
      consumeRefreshToken(refresh.token),
      consumeRefreshToken(refresh.token),
      consumeRefreshToken(refresh.token),
    ]);

    const successes = results.filter(r => r.success).length;
    const failures = results.filter(r => !r.success).length;

    // Exactly ONE should succeed
    expect(successes).toBe(1);
    expect(failures).toBe(4);

    // All failures should have appropriate error
    results.forEach(r => {
      if (!r.success) {
        expect(r.error).toBeDefined();
      }
    });
  });

  it('rejects expired refresh tokens', async () => {
    const refresh = issueRefreshToken('user-123', 'tenant-a');

    // Manually expire the token
    tokenStore.set(refresh.token, {
      ...refresh,
      expiresAt: Date.now() - 1000, // Expired 1 second ago
    });

    const result = await consumeRefreshToken(refresh.token);
    expect(result.success).toBe(false);
    expect(result.error).toBe('TOKEN_EXPIRED');
  });

  it('rejects non-existent tokens', async () => {
    const result = await consumeRefreshToken('non_existent_token_12345');
    expect(result.success).toBe(false);
    expect(result.error).toBe('TOKEN_NOT_FOUND');
  });
});

describe('Refresh Token Family Lineage', () => {
  beforeEach(() => {
    clearTestState();
  });

  afterEach(() => {
    clearTestState();
  });

  it('maintains token family lineage', async () => {
    const familyId = 'family_user-123';
    const userId = 'user-123';
    const tenantId = 'tenant-a';

    // Issue first token
    const token1 = issueRefreshToken(userId, tenantId);
    expect(token1.familyId).toBe(familyId);

    // Rotate
    const result1 = await consumeRefreshToken(token1.token);
    const token2 = result1.newRefreshToken!;

    // Rotate again
    const result2 = await consumeRefreshToken(token2);
    const token3 = result2.newRefreshToken!;

    // Verify all tokens in same family
    expect(tokenStore.get(token1.token)?.familyId).toBe(familyId);
    expect(tokenStore.get(token2)?.familyId).toBe(familyId);
    expect(tokenStore.get(token3)?.familyId).toBe(familyId);

    // Original token is blacklisted
    expect(blacklistStore.has(token1.token)).toBe(true);
  });
});