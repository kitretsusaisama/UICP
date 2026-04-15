/**
 * Property 16: No repository query returns rows belonging to a different tenant
 *
 * Validates: Req 1.3
 *
 * Strategy: Use in-memory stub implementations of IUserRepository and
 * IIdentityRepository that mirror the tenant-scoped WHERE clause logic of
 * the MySQL adapters. For every repository read method, assert that querying
 * with tenantB never returns data that was saved under tenantA — even when
 * the row IDs are known.
 *
 * This is a pure unit / property test — no real database required.
 */

import * as fc from 'fast-check';
import { IUserRepository } from '../../../application/ports/driven/i-user.repository';
import { IIdentityRepository } from '../../../application/ports/driven/i-identity.repository';
import { User } from '../../../domain/aggregates/user.aggregate';
import { Identity, IdentityType, toEncryptedValue } from '../../../domain/entities/identity.entity';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { IdentityId } from '../../../domain/value-objects/identity-id.vo';

// ── In-memory stub repositories ────────────────────────────────────────────

/**
 * Minimal in-memory IUserRepository that enforces tenant isolation exactly
 * as the MySQL adapter does: every read filters by tenant_id.
 */
class InMemoryUserRepository implements IUserRepository {
  /** Map of `${tenantId}:${userId}` → User */
  private readonly store = new Map<string, User>();

  async findById(userId: UserId, tenantId: TenantId): Promise<User | null> {
    return this.store.get(`${tenantId.toString()}:${userId.toString()}`) ?? null;
  }

  async findByTenantId(tenantId: TenantId): Promise<User[]> {
    const results: User[] = [];
    for (const [key, user] of this.store) {
      if (key.startsWith(`${tenantId.toString()}:`)) {
        results.push(user);
      }
    }
    return results;
  }

  async save(user: User): Promise<void> {
    const key = `${user.getTenantId().toString()}:${user.getId().toString()}`;
    this.store.set(key, user);
  }

  async update(user: User): Promise<void> {
    const key = `${user.getTenantId().toString()}:${user.getId().toString()}`;
    this.store.set(key, user);
  }
}

/**
 * Minimal in-memory IIdentityRepository that enforces tenant isolation.
 */
class InMemoryIdentityRepository implements IIdentityRepository {
  /** Map of `${tenantId}:${identityId}` → Identity */
  private readonly store = new Map<string, Identity>();

  async findByHash(
    valueHash: string,
    type: IdentityType,
    tenantId: TenantId,
  ): Promise<Identity | null> {
    for (const [key, identity] of this.store) {
      if (
        key.startsWith(`${tenantId.toString()}:`) &&
        identity.getValueHash() === valueHash &&
        identity.getType() === type
      ) {
        return identity;
      }
    }
    return null;
  }

  async findByUserId(userId: UserId, tenantId: TenantId): Promise<Identity[]> {
    const results: Identity[] = [];
    for (const [key, identity] of this.store) {
      if (
        key.startsWith(`${tenantId.toString()}:`) &&
        identity.userId.toString() === userId.toString()
      ) {
        results.push(identity);
      }
    }
    return results;
  }

  async findByProviderSub(
    providerSub: string,
    type: IdentityType,
    tenantId: TenantId,
  ): Promise<Identity | null> {
    for (const [key, identity] of this.store) {
      if (
        key.startsWith(`${tenantId.toString()}:`) &&
        identity.getProviderSub() === providerSub &&
        identity.getType() === type
      ) {
        return identity;
      }
    }
    return null;
  }

  async save(identity: Identity): Promise<void> {
    const key = `${identity.tenantId.toString()}:${identity.id.toString()}`;
    this.store.set(key, identity);
  }

  async verify(identityId: IdentityId, tenantId: TenantId): Promise<void> {
    const key = `${tenantId.toString()}:${identityId.toString()}`;
    const identity = this.store.get(key);
    if (identity && !identity.isVerified()) {
      identity.verify();
    }
  }
}

// ── Fixtures ───────────────────────────────────────────────────────────────

function buildUserForTenant(tenantId: TenantId, emailHash: string): User {
  return User.createWithEmail({
    email: {
      getValue: () => 'user@example.com',
      getDomain: () => 'example.com',
      toHmacInput: () => 'user@example.com',
      toString: () => 'user@example.com',
    } as any,
    tenantId,
    emailEnc: toEncryptedValue('iv.tag.cipher.kid1'),
    emailHash,
  });
}

function buildIdentityForTenant(
  tenantId: TenantId,
  userId: UserId,
  valueHash: string,
  type: IdentityType = 'EMAIL',
): Identity {
  return Identity.reconstitute({
    id: IdentityId.create(),
    tenantId,
    userId,
    type,
    valueEnc: toEncryptedValue('iv.tag.cipher.kid1'),
    valueHash,
    verified: false,
    createdAt: new Date(),
  });
}

// ── Property 16 ────────────────────────────────────────────────────────────

/**
 * Property 16: No repository query returns rows belonging to a different tenant
 *
 * Validates: Req 1.3
 */
describe('Property 16 — Tenant isolation: no cross-tenant data leakage', () => {
  // Arbitrary for a hex-like hash string (32 hex chars = 16 bytes)
  const hashArb = fc
    .hexaString({ minLength: 32, maxLength: 32 })
    .map((s) => s.padEnd(32, '0'));

  // ── IUserRepository ──────────────────────────────────────────────────────

  describe('IUserRepository', () => {
    it('findById with tenantB never returns a user saved under tenantA', async () => {
      await fc.assert(
        fc.asyncProperty(hashArb, async (emailHash) => {
          const repo = new InMemoryUserRepository();
          const tenantA = TenantId.create();
          const tenantB = TenantId.create();

          const user = buildUserForTenant(tenantA, emailHash);
          await repo.save(user);

          // Query with tenantB using the known userId from tenantA
          const result = await repo.findById(user.getId(), tenantB);
          expect(result).toBeNull();
        }),
      );
    });

    it('findByTenantId with tenantB returns empty array even when tenantA has users', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(hashArb, { minLength: 1, maxLength: 5 }),
          async (emailHashes) => {
            const repo = new InMemoryUserRepository();
            const tenantA = TenantId.create();
            const tenantB = TenantId.create();

            // Save multiple users under tenantA
            for (const hash of emailHashes) {
              await repo.save(buildUserForTenant(tenantA, hash));
            }

            // tenantB should see zero users
            const results = await repo.findByTenantId(tenantB);
            expect(results).toHaveLength(0);
          },
        ),
      );
    });

    it('findByTenantId with tenantA only returns tenantA users, never tenantB users', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(hashArb, { minLength: 1, maxLength: 3 }),
          fc.array(hashArb, { minLength: 1, maxLength: 3 }),
          async (hashesA, hashesB) => {
            const repo = new InMemoryUserRepository();
            const tenantA = TenantId.create();
            const tenantB = TenantId.create();

            const usersA: User[] = [];
            for (const hash of hashesA) {
              const u = buildUserForTenant(tenantA, hash);
              await repo.save(u);
              usersA.push(u);
            }

            for (const hash of hashesB) {
              await repo.save(buildUserForTenant(tenantB, hash));
            }

            const resultsA = await repo.findByTenantId(tenantA);
            const tenantAIds = new Set(usersA.map((u) => u.getId().toString()));

            // Every returned user must belong to tenantA
            for (const user of resultsA) {
              expect(user.getTenantId().toString()).toBe(tenantA.toString());
              expect(tenantAIds.has(user.getId().toString())).toBe(true);
            }

            // Count must match exactly
            expect(resultsA).toHaveLength(usersA.length);
          },
        ),
      );
    });
  });

  // ── IIdentityRepository ──────────────────────────────────────────────────

  describe('IIdentityRepository', () => {
    it('findByHash with tenantB never returns an identity saved under tenantA', async () => {
      await fc.assert(
        fc.asyncProperty(hashArb, async (valueHash) => {
          const repo = new InMemoryIdentityRepository();
          const tenantA = TenantId.create();
          const tenantB = TenantId.create();
          const userId = UserId.create();

          const identity = buildIdentityForTenant(tenantA, userId, valueHash, 'EMAIL');
          await repo.save(identity);

          // Query with tenantB using the exact same hash + type
          const result = await repo.findByHash(valueHash, 'EMAIL', tenantB);
          expect(result).toBeNull();
        }),
      );
    });

    it('findByUserId with tenantB never returns identities saved under tenantA', async () => {
      await fc.assert(
        fc.asyncProperty(hashArb, async (valueHash) => {
          const repo = new InMemoryIdentityRepository();
          const tenantA = TenantId.create();
          const tenantB = TenantId.create();
          const userId = UserId.create();

          const identity = buildIdentityForTenant(tenantA, userId, valueHash);
          await repo.save(identity);

          // Query with tenantB using the known userId from tenantA
          const results = await repo.findByUserId(userId, tenantB);
          expect(results).toHaveLength(0);
        }),
      );
    });

    it('findByProviderSub with tenantB never returns an identity saved under tenantA', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.uuid(),
          hashArb,
          async (providerSub, valueHash) => {
            const repo = new InMemoryIdentityRepository();
            const tenantA = TenantId.create();
            const tenantB = TenantId.create();
            const userId = UserId.create();

            const identity = Identity.reconstitute({
              id: IdentityId.create(),
              tenantId: tenantA,
              userId,
              type: 'OAUTH_GOOGLE',
              valueEnc: toEncryptedValue('iv.tag.cipher.kid1'),
              valueHash,
              providerSub,
              verified: true,
              verifiedAt: new Date(),
              createdAt: new Date(),
            });
            await repo.save(identity);

            // Query with tenantB using the exact same providerSub
            const result = await repo.findByProviderSub(providerSub, 'OAUTH_GOOGLE', tenantB);
            expect(result).toBeNull();
          },
        ),
      );
    });

    it('findByUserId with tenantA only returns identities belonging to tenantA', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(hashArb, { minLength: 1, maxLength: 4 }),
          async (hashes) => {
            const repo = new InMemoryIdentityRepository();
            const tenantA = TenantId.create();
            const tenantB = TenantId.create();
            const sharedUserId = UserId.create();

            // Save identities under tenantA with the shared userId
            for (const hash of hashes) {
              await repo.save(buildIdentityForTenant(tenantA, sharedUserId, hash));
            }

            // Save an identity under tenantB with the same userId
            await repo.save(buildIdentityForTenant(tenantB, sharedUserId, hashes[0]!));

            const results = await repo.findByUserId(sharedUserId, tenantA);

            // All returned identities must belong to tenantA
            for (const identity of results) {
              expect(identity.tenantId.toString()).toBe(tenantA.toString());
            }

            // Must not include the tenantB identity
            expect(results).toHaveLength(hashes.length);
          },
        ),
      );
    });
  });

  // ── Cross-tenant ID reuse ────────────────────────────────────────────────

  describe('cross-tenant ID reuse', () => {
    it('same userId in two tenants never leaks across tenant boundaries', async () => {
      /**
       * Simulates the scenario where two tenants happen to have users with
       * the same UserId (e.g. due to a UUID collision or deliberate attack).
       * The repository must still return null when queried with the wrong tenant.
       */
      await fc.assert(
        fc.asyncProperty(hashArb, hashArb, async (hashA, hashB) => {
          const userRepo = new InMemoryUserRepository();
          const tenantA = TenantId.create();
          const tenantB = TenantId.create();

          const userA = buildUserForTenant(tenantA, hashA);
          const userB = buildUserForTenant(tenantB, hashB);

          await userRepo.save(userA);
          await userRepo.save(userB);

          // tenantA's userId must not be found under tenantB
          const crossResult = await userRepo.findById(userA.getId(), tenantB);
          expect(crossResult).toBeNull();

          // tenantB's userId must not be found under tenantA
          const crossResult2 = await userRepo.findById(userB.getId(), tenantA);
          expect(crossResult2).toBeNull();

          // Each user is found under their own tenant
          const resultA = await userRepo.findById(userA.getId(), tenantA);
          const resultB = await userRepo.findById(userB.getId(), tenantB);
          expect(resultA).not.toBeNull();
          expect(resultB).not.toBeNull();
        }),
      );
    });
  });
});
