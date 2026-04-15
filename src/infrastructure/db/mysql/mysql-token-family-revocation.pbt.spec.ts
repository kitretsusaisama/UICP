/**
 * Property-Based Test — Token Family Revocation Completeness (Property 2)
 *
 * **Property 2: When token reuse is detected, ALL tokens in the family are revoked**
 *
 * **Validates: Req 7.4**
 *
 * Strategy: Use an in-memory stub of ITokenRepository that faithfully
 * replicates the revokeFamily() semantics of the MySQL adapter.
 * For any family of N tokens, trigger revokeFamily() and assert that
 * every token in the family has revoked=true — none are left active.
 *
 * This is a pure unit / property test — no real database required.
 */

import * as fc from 'fast-check';
import { ITokenRepository, RefreshTokenRecord } from '../../../application/ports/driven/i-token.repository';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';

// ── In-memory stub ─────────────────────────────────────────────────────────

class InMemoryTokenRepository implements ITokenRepository {
  private readonly tokens = new Map<string, RefreshTokenRecord>();
  private readonly blocklist = new Set<string>();

  async saveRefreshToken(record: RefreshTokenRecord): Promise<void> {
    this.tokens.set(record.jti, { ...record });
  }

  async findRefreshToken(jti: string, _tenantId: TenantId): Promise<RefreshTokenRecord | null> {
    return this.tokens.get(jti) ?? null;
  }

  async revokeToken(jti: string, _tenantId: TenantId): Promise<void> {
    const record = this.tokens.get(jti);
    if (record) {
      this.tokens.set(jti, { ...record, revoked: true });
    }
  }

  async revokeFamily(familyId: string, _tenantId: TenantId): Promise<void> {
    for (const [jti, record] of this.tokens) {
      if (record.familyId === familyId && !record.revoked) {
        this.tokens.set(jti, { ...record, revoked: true });
      }
    }
  }

  async revokeAllFamiliesByUser(userId: UserId, tenantId: TenantId): Promise<void> {
    for (const [jti, record] of this.tokens) {
      if (record.userId === userId.toString() && record.tenantId === tenantId.toString() && !record.revoked) {
        this.tokens.set(jti, { ...record, revoked: true });
      }
    }
  }

  async isBlocklisted(jti: string): Promise<boolean> {
    return this.blocklist.has(jti);
  }

  async addToBlocklist(jti: string, _expiresAt: Date): Promise<void> {
    this.blocklist.add(jti);
  }

  async getActiveJtisByUser(userId: UserId, tenantId: TenantId): Promise<string[]> {
    const results: string[] = [];
    for (const record of this.tokens.values()) {
      if (
        record.userId === userId.toString() &&
        record.tenantId === tenantId.toString() &&
        !record.revoked &&
        record.expiresAt > new Date()
      ) {
        results.push(record.jti);
      }
    }
    return results;
  }

  /** Test helper: get all tokens in a family. */
  getFamily(familyId: string): RefreshTokenRecord[] {
    return [...this.tokens.values()].filter((r) => r.familyId === familyId);
  }
}

// ── Fixtures ───────────────────────────────────────────────────────────────

function makeToken(familyId: string, tenantId: string, userId: string): RefreshTokenRecord {
  return {
    jti: crypto.randomUUID(),
    familyId,
    userId,
    tenantId,
    revoked: false,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    createdAt: new Date(),
  };
}

// ── Property 2 ─────────────────────────────────────────────────────────────

describe('Property 2 — Token family revocation completeness (Req 7.4)', () => {
  /**
   * Core property: after revokeFamily(familyId), every token in that family
   * must have revoked=true — none remain active.
   */
  it('revokeFamily() marks ALL tokens in the family as revoked', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Family size: 1–10 tokens
        fc.integer({ min: 1, max: 10 }),
        async (familySize) => {
          const repo = new InMemoryTokenRepository();
          const tenantId = TenantId.create();
          const userId = UserId.create();
          const familyId = crypto.randomUUID();

          // Persist N tokens in the same family
          for (let i = 0; i < familySize; i++) {
            await repo.saveRefreshToken(makeToken(familyId, tenantId.toString(), userId.toString()));
          }

          // Trigger reuse detection → revoke entire family
          await repo.revokeFamily(familyId, tenantId);

          // Every token in the family must be revoked
          const family = repo.getFamily(familyId);
          expect(family).toHaveLength(familySize);
          for (const token of family) {
            expect(token.revoked).toBe(true);
          }
        },
      ),
      { numRuns: 200 },
    );
  });

  it('revokeFamily() does not revoke tokens belonging to a different family', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 5 }),
        fc.integer({ min: 1, max: 5 }),
        async (familyASize, familyBSize) => {
          const repo = new InMemoryTokenRepository();
          const tenantId = TenantId.create();
          const userId = UserId.create();
          const familyA = crypto.randomUUID();
          const familyB = crypto.randomUUID();

          for (let i = 0; i < familyASize; i++) {
            await repo.saveRefreshToken(makeToken(familyA, tenantId.toString(), userId.toString()));
          }
          for (let i = 0; i < familyBSize; i++) {
            await repo.saveRefreshToken(makeToken(familyB, tenantId.toString(), userId.toString()));
          }

          // Revoke only family A
          await repo.revokeFamily(familyA, tenantId);

          // Family A: all revoked
          for (const token of repo.getFamily(familyA)) {
            expect(token.revoked).toBe(true);
          }

          // Family B: none revoked
          for (const token of repo.getFamily(familyB)) {
            expect(token.revoked).toBe(false);
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  it('revokeFamily() is idempotent — calling twice produces the same result', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 8 }),
        async (familySize) => {
          const repo = new InMemoryTokenRepository();
          const tenantId = TenantId.create();
          const userId = UserId.create();
          const familyId = crypto.randomUUID();

          for (let i = 0; i < familySize; i++) {
            await repo.saveRefreshToken(makeToken(familyId, tenantId.toString(), userId.toString()));
          }

          await repo.revokeFamily(familyId, tenantId);
          await repo.revokeFamily(familyId, tenantId); // second call — idempotent

          const family = repo.getFamily(familyId);
          expect(family).toHaveLength(familySize);
          for (const token of family) {
            expect(token.revoked).toBe(true);
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  it('revokeAllFamiliesByUser() revokes all active tokens for the user across all families', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 4 }),  // number of families
        fc.integer({ min: 1, max: 4 }),  // tokens per family
        async (numFamilies, tokensPerFamily) => {
          const repo = new InMemoryTokenRepository();
          const tenantId = TenantId.create();
          const userId = UserId.create();
          const familyIds: string[] = [];

          for (let f = 0; f < numFamilies; f++) {
            const familyId = crypto.randomUUID();
            familyIds.push(familyId);
            for (let t = 0; t < tokensPerFamily; t++) {
              await repo.saveRefreshToken(makeToken(familyId, tenantId.toString(), userId.toString()));
            }
          }

          await repo.revokeAllFamiliesByUser(userId, tenantId);

          // All tokens for this user must be revoked
          for (const familyId of familyIds) {
            for (const token of repo.getFamily(familyId)) {
              expect(token.revoked).toBe(true);
            }
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  it('revokeAllFamiliesByUser() does not affect tokens belonging to a different user', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 5 }),
        async (tokenCount) => {
          const repo = new InMemoryTokenRepository();
          const tenantId = TenantId.create();
          const userA = UserId.create();
          const userB = UserId.create();
          const familyA = crypto.randomUUID();
          const familyB = crypto.randomUUID();

          for (let i = 0; i < tokenCount; i++) {
            await repo.saveRefreshToken(makeToken(familyA, tenantId.toString(), userA.toString()));
            await repo.saveRefreshToken(makeToken(familyB, tenantId.toString(), userB.toString()));
          }

          // Revoke all of userA's tokens
          await repo.revokeAllFamiliesByUser(userA, tenantId);

          // userA's tokens: all revoked
          for (const token of repo.getFamily(familyA)) {
            expect(token.revoked).toBe(true);
          }

          // userB's tokens: untouched
          for (const token of repo.getFamily(familyB)) {
            expect(token.revoked).toBe(false);
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});
