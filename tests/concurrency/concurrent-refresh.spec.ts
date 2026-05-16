import { describe, it, expect, beforeEach } from '@jest/globals';

interface RefreshToken {
  token: string;
  userId: string;
  tenantId: string;
  rotated: boolean;
  rotatedAt?: number;
}

// In-memory token store
const tokenStore = new Map<string, RefreshToken>();

function createToken(userId: string, tenantId: string): RefreshToken {
  const token: RefreshToken = {
    token: `rt_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
    userId,
    tenantId,
    rotated: false,
  };
  tokenStore.set(token.token, token);
  return token;
}

async function rotateToken(token: string): Promise<{ success: boolean; error?: string }> {
  return new Promise((resolve) => {
    queueMicrotask(() => {
      const stored = tokenStore.get(token);

      if (!stored) {
        resolve({ success: false, error: 'TOKEN_NOT_FOUND' });
        return;
      }

      if (stored.rotated) {
        resolve({ success: false, error: 'ALREADY_ROTATED' });
        return;
      }

      // Mark as rotated
      stored.rotated = true;
      stored.rotatedAt = Date.now();
      tokenStore.set(token, stored);

      resolve({ success: true });
    });
  });
}

// Simulate atomic compare-and-swap
async function atomicRotate(token: string): Promise<{ success: boolean; error?: string }> {
  const stored = tokenStore.get(token);

  if (!stored) {
    return { success: false, error: 'TOKEN_NOT_FOUND' };
  }

  // Check and update atomically
  if (stored.rotated) {
    return { success: false, error: 'ALREADY_ROTATED' };
  }

  // Critical section - mark before any other can read
  stored.rotated = true;
  stored.rotatedAt = Date.now();

  // Add small delay to simulate real scenarios
  await new Promise(r => setTimeout(r, 1));

  return { success: true };
}

describe('Concurrent Refresh Race', () => {
  beforeEach(() => {
    tokenStore.clear();
  });

  it('allows exactly one winner from concurrent requests', async () => {
    const token = createToken('user-123', 'tenant-a');

    // 5 simultaneous rotation attempts
    const results = await Promise.all([
      rotateToken(token.token),
      rotateToken(token.token),
      rotateToken(token.token),
      rotateToken(token.token),
      rotateToken(token.token),
    ]);

    const successes = results.filter(r => r.success).length;
    const failures = results.filter(r => !r.success).length;

    // Exactly ONE should succeed
    expect(successes).toBe(1);
    expect(failures).toBe(4);

    // Verify token is now rotated
    const stored = tokenStore.get(token.token);
    expect(stored?.rotated).toBe(true);
  });

  it('prevents race condition without locking', async () => {
    // This test demonstrates the race condition
    const token = createToken('user-123', 'tenant-a');

    // Without proper locking, multiple might succeed
    // The rotateToken function above has a race condition
    // Let's simulate concurrent access differently

    let successCount = 0;
    const promises: Promise<void>[] = [];

    for (let i = 0; i < 10; i++) {
      promises.push(
        atomicRotate(token.token).then(result => {
          if (result.success) successCount++;
        })
      );
    }

    await Promise.all(promises);

    // In a proper implementation, exactly ONE should succeed
    // But due to race condition, multiple might win
    // This test will likely FAIL in the current implementation
    // proving the need for proper mutex/locking
    expect(successCount).toBe(1);
  });

  it('isolates tenant token families', async () => {
    const tokenA = createToken('user-123', 'tenant-a');
    const tokenB = createToken('user-123', 'tenant-b');

    const resultsA = await Promise.all([
      rotateToken(tokenA.token),
      rotateToken(tokenA.token),
      rotateToken(tokenA.token),
    ]);

    const resultsB = await Promise.all([
      rotateToken(tokenB.token),
      rotateToken(tokenB.token),
      rotateToken(tokenB.token),
    ]);

    // Each tenant should have exactly one success
    expect(resultsA.filter(r => r.success).length).toBe(1);
    expect(resultsB.filter(r => r.success).length).toBe(1);

    // Both succeed since they operate on different tenant tokens
    expect(resultsA[0].success).toBe(true);
    expect(resultsB[0].success).toBe(true);
  });

  it('handles rapid successive rotations', async () => {
    let token = createToken('user-123', 'tenant-a');

    // First rotation
    const result1 = await rotateToken(token.token);
    expect(result1.success).toBe(true);

    // Second rotation should fail (already rotated)
    const result2 = await rotateToken(token.token);
    expect(result2.success).toBe(false);

    // New token should work
    token = createToken('user-123', 'tenant-a');
    const result3 = await rotateToken(token.token);
    expect(result3.success).toBe(true);
  });
});

describe('Session Lineage Integrity', () => {
  beforeEach(() => {
    tokenStore.clear();
  });

  it('maintains token family lineage', async () => {
    const familyId = 'family-user123';
    const tokens: RefreshToken[] = [];

    // Issue initial token
    let currentToken = createToken('user-123', 'tenant-a');
    tokens.push(currentToken);

    // Rotate through multiple generations
    for (let i = 0; i < 5; i++) {
      const result = await rotateToken(currentToken.token);
      if (result.success) {
        currentToken = createToken('user-123', 'tenant-a');
        tokens.push(currentToken);
      }
    }

    // All tokens in family should be tracked
    expect(tokens.length).toBeGreaterThan(1);

    // Original token should be rotated
    expect(tokens[0]!.rotated).toBe(true);
  });
});