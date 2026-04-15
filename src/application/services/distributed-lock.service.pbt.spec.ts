import * as fc from 'fast-check';
import { OtpService, OtpPurpose } from './otp.service';
import { ICachePort } from '../ports/driven/i-cache.port';
import { DomainException } from '../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../domain/exceptions/domain-error-codes';
import { ConfigService } from '@nestjs/config';

/**
 * Property-Based Test — OTP Single-Use Guarantee (Property 5)
 *
 * **Property 5: verify(C) succeeds ⟹ verify(C) on subsequent call throws ALREADY_USED**
 *
 * **Validates: Req 6.2, Req 6.4**
 *
 * For any valid OTP code and any user ID:
 *   - The first verifyAndConsume() call succeeds
 *   - Any subsequent verifyAndConsume() call throws OTP_ALREADY_USED
 *
 * This guarantees the single-use invariant holds across all possible inputs.
 */

/** Build an OtpService with an in-memory cache mock. */
function makeService(): { svc: OtpService; store: Map<string, string> } {
  const store = new Map<string, string>();

  const cache: ICachePort = {
    get: jest.fn(async (key: string) => store.get(key) ?? null),
    set: jest.fn(async (key: string, value: string) => { store.set(key, value); }),
    del: jest.fn(async (key: string) => { store.delete(key); }),
    getdel: jest.fn(async (key: string) => {
      const value = store.get(key) ?? null;
      if (value !== null) store.delete(key);
      return value;
    }),
    sismember: jest.fn(async () => false),
    sadd: jest.fn(async () => 0),
    srem: jest.fn(async () => 0),
    smembers: jest.fn(async () => []),
    incr: jest.fn(async () => 0),
    expire: jest.fn(async () => true),
  };

  const config = {
    get: (key: string, defaultValue?: unknown) => {
      if (key === 'OTP_TTL_S') return 300;
      return defaultValue;
    },
  } as unknown as ConfigService;

  return { svc: new OtpService(config, cache), store };
}

/** Arbitrary for a 6-digit zero-padded OTP code string. */
const otpCodeArb = fc.integer({ min: 0, max: 999_999 }).map((n) =>
  n.toString().padStart(6, '0'),
);

/** Arbitrary for a non-empty user ID string. */
const userIdArb = fc.uuid();

/** Arbitrary for an OTP purpose. */
const purposeArb = fc.constantFrom<OtpPurpose>(
  'IDENTITY_VERIFICATION',
  'MFA',
  'PASSWORD_RESET',
);

describe('Property 5 — OTP single-use guarantee (Req 6.2, Req 6.4)', () => {
  it('first verify succeeds; second verify throws OTP_ALREADY_USED', async () => {
    await fc.assert(
      fc.asyncProperty(otpCodeArb, userIdArb, purposeArb, async (code, userId, purpose) => {
        const { svc } = makeService();

        // Store the OTP
        await svc.store(userId, purpose, code);

        // First call must succeed
        await svc.verifyAndConsume(userId, code, purpose);

        // Second call must throw OTP_ALREADY_USED regardless of submitted code
        let threw = false;
        let errorCode: string | undefined;
        try {
          await svc.verifyAndConsume(userId, code, purpose);
        } catch (err) {
          threw = true;
          if (err instanceof DomainException) {
            errorCode = err.errorCode;
          }
        }

        return threw && errorCode === DomainErrorCode.OTP_ALREADY_USED;
      }),
      { numRuns: 200 },
    );
  });

  it('second verify with a different code also throws OTP_ALREADY_USED (not INVALID_OTP)', async () => {
    await fc.assert(
      fc.asyncProperty(
        otpCodeArb,
        otpCodeArb,
        userIdArb,
        purposeArb,
        async (code, differentCode, userId, purpose) => {
          const { svc } = makeService();

          await svc.store(userId, purpose, code);

          // First call succeeds
          await svc.verifyAndConsume(userId, code, purpose);

          // Second call with any code must throw OTP_ALREADY_USED
          let threw = false;
          let errorCode: string | undefined;
          try {
            await svc.verifyAndConsume(userId, differentCode, purpose);
          } catch (err) {
            threw = true;
            if (err instanceof DomainException) {
              errorCode = err.errorCode;
            }
          }

          return threw && errorCode === DomainErrorCode.OTP_ALREADY_USED;
        },
      ),
      { numRuns: 200 },
    );
  });

  it('single-use guarantee holds across all three OTP purposes independently', async () => {
    await fc.assert(
      fc.asyncProperty(otpCodeArb, userIdArb, async (code, userId) => {
        const purposes: OtpPurpose[] = ['IDENTITY_VERIFICATION', 'MFA', 'PASSWORD_RESET'];

        for (const purpose of purposes) {
          const { svc } = makeService();

          await svc.store(userId, purpose, code);

          // First call succeeds
          await svc.verifyAndConsume(userId, code, purpose);

          // Second call must throw OTP_ALREADY_USED
          let threw = false;
          let errorCode: string | undefined;
          try {
            await svc.verifyAndConsume(userId, code, purpose);
          } catch (err) {
            threw = true;
            if (err instanceof DomainException) {
              errorCode = err.errorCode;
            }
          }

          if (!threw || errorCode !== DomainErrorCode.OTP_ALREADY_USED) {
            return false;
          }
        }

        return true;
      }),
      { numRuns: 100 },
    );
  });
});
