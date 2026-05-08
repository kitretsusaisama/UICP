/**
 * Property-Based Test — Token Family Revocation Completeness (Property 2)
 *
 * **Property 2: When token reuse is detected, ALL tokens in the family are revoked**
 *
 * **Validates: Req 7.4**
 *
 * For any token family of N tokens:
 *   - Submitting an already-rotated (revoked) refresh token triggers reuse detection
 *   - After reuse detection, every token in the family has `revoked = true`
 *   - No token in the family can be used for further rotation
 *
 * This guarantees that a stolen refresh token cannot be used to silently
 * maintain access after the legitimate user has already rotated it.
 */

import * as fc from 'fast-check';
import { randomUUID } from 'crypto';
import { RefreshTokenHandler } from './refresh-token.handler';
import { RefreshTokenCommand } from './refresh-token.command';
import { ITokenRepository, RefreshTokenRecord } from '../../ports/driven/i-token.repository';
import { IOutboxRepository } from '../../ports/driven/i-outbox.repository';
import { IUserRepository } from '../../ports/driven/i-user.repository';
import { TokenService } from '../../services/token.service';
import { SessionService } from '../../services/session.service';
import { DistributedLockService } from '../../services/distributed-lock.service';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';

// ── Test RSA key pair (2048-bit, test-only — never used in production) ────────

const TEST_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDjHKc5F5VV3a1N
oWe1bhcllbBHSaT1px2ZtQlFZlSJ23V2jEK4BPiRQzCGP7A2Oi34urq4HYw+Jub1
G9rX5K/vgvjj9BpvvL9O85jMsTyAQXPZ31Q1KdKb2LdhhH2dUJ7KXyakUAiHeJyv
S0uNS0gr7akJUj1+vEfKirNUercx7RALgpEK0ZXYQPXTd4DCscNBmweR5Iz3HcrF
IaKYKFb71vytzLPkoQXWiFVGTxGqFv5v+LjZi03gziNA9NSnYS6FpmIHcEdHf0bR
IWcXP/5FOcLJzZP8n4d/1fTXuTpGX/8PXV+mvCnTFcjBJUcjklyiPhcZQx5Cg22a
sIZ1Sr1tAgMBAAECggEAR1K4y2u2GNS4t8AAJ1CvET0cso6UsRbt61cY1cQouXCD
x5qN22eoPkpZA1gd+TG1PT87I1YYNG6YKpK4XAO0IuZBTqla4gtnEx7aNjJU+zxS
6zHBKr77JrldAdGPd2eZrplKM+D0hMLihgSB8hoZzL3iz4wVxubPLvL3FYlCXflr
CKvCjHiHOmXcR+mmtKSHUuGtv8Wig0BWUTUug+Qd6XY3EZ3JDYTJY6sQqKvesALA
Vlla1xPS9LcFT4WupzrrdaN3BYM6PWgDBxiPXjKxxo2eTv2Sze2tFefTZ5qKrU8Q
eoFbJDfAU6SdU184Wmpiet7A/lk5jN/IHjNTRum2awKBgQD3SrffKdtqLATQRyZM
7uI3Mw8KFBXFRd6ZNU8/GXqEj+O6hB9OlHSB/E/ZXPdvcb7iBnh7yecWugsURKSv
jfbdOGEoVnBNEAHL3p1NSigv5ePKGf5oHlmHCN8uECfw55wPzuizRm6vbVE14DRO
CvAINiCgBl+/RWHDzKDapkrRiwKBgQDrHARpi/6G1ZwrJfAdB8s+bIfwnLS/ztCP
TyLcrkqXWdg5Km6BXTYWZtShjaC0XOhRIxXDi6GT/aWyjj8D3w269wYXrdM1aML2
NDB/MG5fBwMryDvCwG8fcpfOR+BERB6RvUbWD/oiZcGTlOSDYljYY92VXCKKXceU
IAZDBMob5wKBgQDj627K9XYwRf/twxXu5GGFBL9Ax8BFAR+nz7WJb783PLNkre94
6mTzhQxHR2MayRholBQp663ciX46oQW0dEDqJdOObRS2QiGVuEj8+nNNqjGnjQup
BQf46FliyCs34xA4lbhtu2W6tCOcZ1dt8rDGsLSjKRzIWndAEnLS81+T/wKBgArY
RP/VXE095zE6U8QTCvX7LZ4UrGW4lXg2z0XcqEYo98dTRLuk4AzSe3ZkQQhwzKqJ
csSNWUupRI5i71cvX8PDBz3qX7az+WI/8Ai95Clv+l53owINvFJ4B7aVLCwZ9EsG
rxDKteAGT5KOKKhCzhRVLvBnypQVVVJo08EdpHD7AoGBALRIITVjKLYItWwkOGB4
n3zdOqyd5So24aV5oX140coJr3ICpCQgnGZu605Ljz7vdNDyMHLLIx8/OjtH80Kg
6G1G8PBtYJBzgWfVyB5//ODXKPdiIxolEtSY4p+JGVNOKvAaMv5rDgat8p/LNh5r
YBX9MTVFi/weJpcYi6Qhs0gf
-----END PRIVATE KEY-----`;

const TEST_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4xynOReVVd2tTaFntW4X
JZWwR0mk9acdmbUJRWZUidt1doxCuAT4kUMwhj+wNjot+Lq6uB2MPibm9Rva1+Sv
74L44/Qab7y/TvOYzLE8gEFz2d9UNSnSm9i3YYR9nVCeyl8mpFAIh3icr0tLjUtI
K+2pCVI9frxHyoqzVHq3Me0QC4KRCtGV2ED103eAwrHDQZsHkeSM9x3KxSGimChW
+9b8rcyz5KEF1ohVRk8Rqhb+b/i42YtN4M4jQPTUp2EuhaZiB3BHR39G0SFnFz/+
RTnCyc2T/J+Hf9X017k6Rl//D11fprwp0xXIwSVHI5Jcoj4XGUMeQoNtmrCGdUq9
bQIDAQAB
-----END PUBLIC KEY-----`;

// ── In-memory token repository ────────────────────────────────────────────────

/**
 * In-memory ITokenRepository that faithfully implements revokeFamily()
 * by marking every token sharing the same familyId as revoked.
 */
class InMemoryTokenRepository implements ITokenRepository {
  private readonly tokens = new Map<string, RefreshTokenRecord>();

  seed(records: RefreshTokenRecord[]): void {
    for (const r of records) {
      this.tokens.set(r.jti, { ...r });
    }
  }

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

  async rotateRefreshToken(oldJti: string, tenantId: TenantId, newRecord: RefreshTokenRecord): Promise<void> {
    await this.revokeToken(oldJti, tenantId);
    await this.saveRefreshToken(newRecord);
  }

  /** Core contract under test: marks ALL tokens in the family as revoked. */
  async revokeFamily(familyId: string, _tenantId: TenantId): Promise<void> {
    for (const [jti, record] of this.tokens.entries()) {
      if (record.familyId === familyId) {
        this.tokens.set(jti, { ...record, revoked: true });
      }
    }
  }

  async revokeAllFamiliesByUser(_userId: UserId, _tenantId: TenantId): Promise<void> {
    for (const [jti, record] of this.tokens.entries()) {
      this.tokens.set(jti, { ...record, revoked: true });
    }
  }

  async isBlocklisted(_jti: string): Promise<boolean> {
    return false;
  }

  async addToBlocklist(_jti: string, _expiresAt: Date): Promise<void> {}

  async getActiveJtisByUser(_userId: UserId, _tenantId: TenantId): Promise<string[]> {
    return [];
  }

  /** Inspect all tokens belonging to a family — used by property assertions. */
  getFamilyTokens(familyId: string): RefreshTokenRecord[] {
    return Array.from(this.tokens.values()).filter((r) => r.familyId === familyId);
  }

  /** Return all stored tokens — used for cross-family isolation assertions. */
  getAllTokens(): RefreshTokenRecord[] {
    return Array.from(this.tokens.values());
  }
}

// ── Test fixture factory ──────────────────────────────────────────────────────

interface TestFixture {
  handler: RefreshTokenHandler;
  tokenService: TokenService;
  tokenRepo: InMemoryTokenRepository;
  tenantId: TenantId;
  userId: UserId;
}

function buildFixture(): TestFixture {
  const tokenRepo = new InMemoryTokenRepository();

  const outboxRepo: IOutboxRepository = {
    insertWithinTransaction: jest.fn().mockResolvedValue(undefined),
    claimPendingBatch: jest.fn().mockResolvedValue([]),
    markPublished: jest.fn().mockResolvedValue(undefined),
    markFailed: jest.fn().mockResolvedValue(undefined),
    moveToDlq: jest.fn().mockResolvedValue(undefined),
  };

  const userRepo: IUserRepository = {
    findById: jest.fn().mockResolvedValue(null),
    findByTenantId: jest.fn().mockResolvedValue([]),
    save: jest.fn().mockResolvedValue(undefined),
    update: jest.fn().mockResolvedValue(undefined),
  };

  const config = {
    get: (key: string, defaultValue?: unknown) => {
      const values: Record<string, unknown> = {
        JWT_PRIVATE_KEY: TEST_PRIVATE_KEY,
        JWT_PUBLIC_KEY: TEST_PUBLIC_KEY,
        JWT_KID: 'test-kid-1',
        JWT_ISSUER: 'https://uicp.test',
        JWT_AUDIENCE: 'uicp-api',
        JWT_ACCESS_TOKEN_TTL_S: 900,
        JWT_REFRESH_TOKEN_TTL_S: 604800,
      };
      return key in values ? values[key] : defaultValue;
    },
    getOrThrow: (key: string) => {
      const values: Record<string, unknown> = {
        JWT_PUBLIC_KEY: TEST_PUBLIC_KEY,
        JWT_KID: 'test-kid-1',
        JWT_ISSUER: 'https://uicp.test',
        JWT_AUDIENCE: 'uicp-api',
      };
      if (!(key in values)) throw new Error(`Missing required config: ${key}`);
      return values[key];
    },
  } as any;

  const tokenService = new TokenService(config, tokenRepo);

  const sessionService = {
    findById: jest.fn().mockResolvedValue(null),
    createSession: jest.fn().mockImplementation(async () => ({
      id: { toString: () => randomUUID() },
      isMfaVerified: () => false,
      getMfaVerifiedAt: () => undefined,
      deviceFingerprint: undefined,
    })),
    invalidateAll: jest.fn().mockResolvedValue(undefined),
  } as unknown as SessionService;

  // Lock service passes through to the callback immediately (no real Redis needed)
  const lockService = {
    withLock: jest.fn().mockImplementation(
      async (_key: string, _ttl: number, fn: () => Promise<unknown>) => fn(),
    ),
  } as unknown as DistributedLockService;

  const runtimeIdentityService = {
    ensureForLegacyUser: jest.fn().mockImplementation((user) => Promise.resolve({
      principalId: user.getId().toString(),
      tenantId: user.getTenantId().toString(),
      membershipId: 'membership-id',
      actorId: 'actor-id',
    })),
  } as any;

  const handler = new RefreshTokenHandler(
    tokenRepo,
    outboxRepo,
    userRepo,
    tokenService,
    sessionService,
    runtimeIdentityService,
    lockService,
  );

  const tenantId = TenantId.from('a1b2c3d4-e5f6-4789-abcd-ef0123456789');
  const userId = UserId.from('b2c3d4e5-f6a7-4890-9bcd-ef0123456789');

  return { handler, tokenService, tokenRepo, tenantId, userId };
}

// ── Arbitraries ───────────────────────────────────────────────────────────────

/** Generate a family size between 2 and 8 tokens (at least 2 so one can be rotated). */
const familySizeArb = fc.integer({ min: 2, max: 8 });

// ── Property 2: Token family revocation completeness ─────────────────────────

describe('Property 2 — Token family revocation completeness (Req 7.4)', () => {
  it(
    'when reuse is detected, ALL tokens in the family are revoked regardless of family size',
    async () => {
      /**
       * **Property 2: revokeFamily(fid) marks every token with familyId=fid as revoked**
       *
       * For any family of N tokens where the first token has already been rotated
       * (revoked=true), submitting that rotated token to the refresh handler MUST:
       *   1. Throw REFRESH_TOKEN_REUSE
       *   2. Leave every token in the family with revoked=true
       *
       * This prevents an attacker who stole a rotated token from maintaining
       * access by exploiting a partial-revocation bug.
       */
      await fc.assert(
        fc.asyncProperty(familySizeArb, async (familySize) => {
          const { handler, tokenService, tokenRepo, tenantId, userId } = buildFixture();

          const familyId = randomUUID();
          const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

          // Mint N refresh tokens for the same family
          const mintedTokens: Array<{ token: string; jti: string }> = [];
          for (let i = 0; i < familySize; i++) {
            const { token, jti } = await tokenService.mintRefreshToken(userId, tenantId, familyId);
            mintedTokens.push({ token, jti });
          }

          // Seed the repository: first token is already rotated (revoked=true),
          // the rest are still active (revoked=false).
          // This simulates: legitimate user rotated token[0] → token[1] → ...
          // Attacker now replays token[0] (the already-rotated one).
          tokenRepo.seed(
            mintedTokens.map(({ jti }, idx) => ({
              jti,
              familyId,
              userId: userId.toString(),
              tenantId: tenantId.toString(),
              revoked: idx === 0, // first token already rotated
              expiresAt,
              createdAt: new Date(),
            })),
          );

          // Submit the already-rotated token — this is the reuse attack
          const rotatedToken = mintedTokens[0]!.token;
          let threwReuseError = false;

          try {
            await handler.handle(
              new RefreshTokenCommand(tenantId.toString(), rotatedToken),
            );
          } catch (err) {
            if (
              err instanceof DomainException &&
              err.errorCode === DomainErrorCode.REFRESH_TOKEN_REUSE
            ) {
              threwReuseError = true;
            } else {
              throw err; // unexpected error — re-throw to fail the test
            }
          }

          // Assert 1: handler threw REFRESH_TOKEN_REUSE
          expect(threwReuseError).toBe(true);

          // Assert 2: every token in the family is now revoked
          const familyTokens = tokenRepo.getFamilyTokens(familyId);
          expect(familyTokens).toHaveLength(familySize);

          for (const record of familyTokens) {
            expect(record.revoked).toBe(true);
          }
        }),
        { numRuns: 200 },
      );
    },
    30_000,
  );

  it(
    'revocation is scoped to the attacked family — tokens in other families are unaffected',
    async () => {
      /**
       * **Cross-family isolation: revokeFamily(fid) must not revoke tokens in other families**
       *
       * Validates: Req 7.4 (negative case — no collateral revocation)
       *
       * When reuse is detected in family A, tokens in family B belonging to the
       * same user must remain unrevoked.
       */
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 1, max: 5 }),
          async (bystanterFamilySize) => {
            const { handler, tokenService, tokenRepo, tenantId, userId } = buildFixture();

            const attackedFamilyId = randomUUID();
            const bystanderFamilyId = randomUUID();
            const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

            // Attacked family: 2 tokens, first already rotated
            const { token: rotatedToken, jti: rotatedJti } = await tokenService.mintRefreshToken(
              userId,
              tenantId,
              attackedFamilyId,
            );
            const { jti: activeJti } = await tokenService.mintRefreshToken(
              userId,
              tenantId,
              attackedFamilyId,
            );

            // Bystander family: N active tokens
            const bystanderJtis: string[] = [];
            for (let i = 0; i < bystanterFamilySize; i++) {
              const { jti } = await tokenService.mintRefreshToken(userId, tenantId, bystanderFamilyId);
              bystanderJtis.push(jti);
            }

            tokenRepo.seed([
              {
                jti: rotatedJti,
                familyId: attackedFamilyId,
                userId: userId.toString(),
                tenantId: tenantId.toString(),
                revoked: true, // already rotated — this is the replayed token
                expiresAt,
                createdAt: new Date(),
              },
              {
                jti: activeJti,
                familyId: attackedFamilyId,
                userId: userId.toString(),
                tenantId: tenantId.toString(),
                revoked: false,
                expiresAt,
                createdAt: new Date(),
              },
              ...bystanderJtis.map((jti) => ({
                jti,
                familyId: bystanderFamilyId,
                userId: userId.toString(),
                tenantId: tenantId.toString(),
                revoked: false,
                expiresAt,
                createdAt: new Date(),
              })),
            ]);

            // Trigger reuse on the attacked family
            try {
              await handler.handle(
                new RefreshTokenCommand(tenantId.toString(), rotatedToken),
              );
            } catch (err) {
              if (
                !(err instanceof DomainException) ||
                err.errorCode !== DomainErrorCode.REFRESH_TOKEN_REUSE
              ) {
                throw err;
              }
            }

            // Attacked family: all revoked
            const attackedTokens = tokenRepo.getFamilyTokens(attackedFamilyId);
            for (const record of attackedTokens) {
              expect(record.revoked).toBe(true);
            }

            // Bystander family: all still active
            const bystanderTokens = tokenRepo.getFamilyTokens(bystanderFamilyId);
            expect(bystanderTokens).toHaveLength(bystanterFamilySize);
            for (const record of bystanderTokens) {
              expect(record.revoked).toBe(false);
            }
          },
        ),
        { numRuns: 200 },
      );
    },
    30_000,
  );

  it(
    'a valid (non-rotated) refresh token does NOT trigger family revocation',
    async () => {
      /**
       * **Negative case: legitimate rotation must not revoke the family**
       *
       * Validates: Req 7.3 (normal rotation path)
       *
       * When a non-revoked token is submitted, the handler should succeed
       * (or fail for unrelated reasons like missing user), but must NOT
       * call revokeFamily on the token's family.
       */
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 1, max: 5 }),
          async (extraTokenCount) => {
            const { handler, tokenService, tokenRepo, tenantId, userId } = buildFixture();

            const familyId = randomUUID();
            const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

            // The token we will submit — not yet rotated
            const { token: validToken, jti: validJti } = await tokenService.mintRefreshToken(
              userId,
              tenantId,
              familyId,
            );

            // Additional tokens in the same family (all active)
            const extraJtis: string[] = [];
            for (let i = 0; i < extraTokenCount; i++) {
              const { jti } = await tokenService.mintRefreshToken(userId, tenantId, familyId);
              extraJtis.push(jti);
            }

            tokenRepo.seed([
              {
                jti: validJti,
                familyId,
                userId: userId.toString(),
                tenantId: tenantId.toString(),
                revoked: false, // not yet rotated — legitimate use
                expiresAt,
                createdAt: new Date(),
              },
              ...extraJtis.map((jti) => ({
                jti,
                familyId,
                userId: userId.toString(),
                tenantId: tenantId.toString(),
                revoked: false,
                expiresAt,
                createdAt: new Date(),
              })),
            ]);

            // Submit the valid token — may fail due to missing user (that's fine),
            // but must NOT throw REFRESH_TOKEN_REUSE
            let threwReuseError = false;
            try {
              await handler.handle(
                new RefreshTokenCommand(tenantId.toString(), validToken),
              );
            } catch (err) {
              if (
                err instanceof DomainException &&
                err.errorCode === DomainErrorCode.REFRESH_TOKEN_REUSE
              ) {
                threwReuseError = true;
              }
              // Other errors (e.g. user not found) are acceptable here
            }

            // The handler must NOT have triggered family revocation
            expect(threwReuseError).toBe(false);

            // The submitted token itself is revoked (normal rotation), but
            // the extra tokens in the family must remain active
            const extraTokens = tokenRepo
              .getFamilyTokens(familyId)
              .filter((r) => extraJtis.includes(r.jti));

            for (const record of extraTokens) {
              expect(record.revoked).toBe(false);
            }
          },
        ),
        { numRuns: 200 },
      );
    },
    30_000,
  );
});
