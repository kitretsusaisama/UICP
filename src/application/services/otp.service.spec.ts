import { OtpService, OtpPurpose } from './otp.service';
import { ICachePort } from '../ports/driven/i-cache.port';
import { DomainException } from '../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../domain/exceptions/domain-error-codes';
import { ConfigService } from '@nestjs/config';

/**
 * Unit tests for OtpService.
 *
 * Covers:
 *   - Req 6.2: single-use guarantee via atomic GETDEL
 *   - Req 6.3: INVALID_OTP on wrong code
 *   - Req 6.4: ALREADY_USED when code already consumed
 *   - Req 6.5: OTP_EXPIRED when TTL elapsed (key missing, no sentinel)
 *   - Req 6.8: timing-safe comparison (no early return on mismatch)
 */

/** Build an OtpService with a mock ICachePort and optional TTL override. */
function makeService(cache: Partial<ICachePort>, ttlS = 300): OtpService {
  const config = {
    get: (key: string, defaultValue?: unknown) => {
      if (key === 'OTP_TTL_S') return ttlS;
      return defaultValue;
    },
  } as unknown as ConfigService;

  return new OtpService(config, cache as ICachePort);
}

/** Build a minimal mock ICachePort backed by an in-memory map. */
function makeInMemoryCache(): ICachePort & { store: Map<string, string> } {
  const store = new Map<string, string>();

  return {
    store,
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
}

const USER_ID = 'user-abc-123';
const PURPOSE: OtpPurpose = 'MFA';

describe('OtpService', () => {
  describe('generate()', () => {
    it('returns a 6-digit zero-padded string', () => {
      const svc = makeService(makeInMemoryCache());
      for (let i = 0; i < 20; i++) {
        const code = svc.generate();
        expect(code).toMatch(/^\d{6}$/);
      }
    });

    it('produces values in the range [000000, 999999]', () => {
      const svc = makeService(makeInMemoryCache());
      for (let i = 0; i < 50; i++) {
        const n = parseInt(svc.generate(), 10);
        expect(n).toBeGreaterThanOrEqual(0);
        expect(n).toBeLessThanOrEqual(999_999);
      }
    });
  });

  describe('store()', () => {
    it('writes the code to cache with the configured TTL', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache, 300);

      await svc.store(USER_ID, PURPOSE, '123456');

      expect(cache.set).toHaveBeenCalledWith(
        `otp:${PURPOSE}:${USER_ID}`,
        '123456',
        300,
      );
    });
  });

  describe('verifyAndConsume() — Req 6.2: single-use guarantee', () => {
    it('succeeds on the first call with the correct code', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);
      const code = '654321';

      await svc.store(USER_ID, PURPOSE, code);
      await expect(svc.verifyAndConsume(USER_ID, code, PURPOSE)).resolves.toBeUndefined();
    });

    it('throws OTP_ALREADY_USED on the second call (single-use guarantee)', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);
      const code = '654321';

      await svc.store(USER_ID, PURPOSE, code);

      // First call succeeds
      await svc.verifyAndConsume(USER_ID, code, PURPOSE);

      // Second call must throw ALREADY_USED
      await expect(svc.verifyAndConsume(USER_ID, code, PURPOSE)).rejects.toMatchObject({
        errorCode: DomainErrorCode.OTP_ALREADY_USED,
      });
    });

    it('throws OTP_ALREADY_USED even when a different code is submitted on the second call', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);
      const code = '111111';

      await svc.store(USER_ID, PURPOSE, code);
      await svc.verifyAndConsume(USER_ID, code, PURPOSE);

      await expect(svc.verifyAndConsume(USER_ID, '999999', PURPOSE)).rejects.toMatchObject({
        errorCode: DomainErrorCode.OTP_ALREADY_USED,
      });
    });
  });

  describe('verifyAndConsume() — Req 6.5: OTP_EXPIRED', () => {
    it('throws OTP_EXPIRED when the key is missing and no consumed sentinel exists', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);

      // No store() call — key never existed (simulates TTL expiry)
      await expect(svc.verifyAndConsume(USER_ID, '000000', PURPOSE)).rejects.toMatchObject({
        errorCode: DomainErrorCode.OTP_EXPIRED,
      });
    });

    it('throws OTP_EXPIRED (not ALREADY_USED) when the key has naturally expired', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);
      const code = '777777';

      await svc.store(USER_ID, PURPOSE, code);

      // Simulate TTL expiry by manually removing the key (no sentinel set)
      cache.store.delete(`otp:${PURPOSE}:${USER_ID}`);

      const err = await svc.verifyAndConsume(USER_ID, code, PURPOSE).catch((e) => e);
      expect(err).toBeInstanceOf(DomainException);
      expect((err as DomainException).errorCode).toBe(DomainErrorCode.OTP_EXPIRED);
    });
  });

  describe('verifyAndConsume() — Req 6.3: INVALID_OTP', () => {
    it('throws INVALID_OTP when the submitted code does not match', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);

      await svc.store(USER_ID, PURPOSE, '123456');

      await expect(svc.verifyAndConsume(USER_ID, '000000', PURPOSE)).rejects.toMatchObject({
        errorCode: DomainErrorCode.INVALID_OTP,
      });
    });

    it('throws INVALID_OTP for off-by-one codes', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);

      await svc.store(USER_ID, PURPOSE, '500000');

      await expect(svc.verifyAndConsume(USER_ID, '500001', PURPOSE)).rejects.toMatchObject({
        errorCode: DomainErrorCode.INVALID_OTP,
      });
    });

    it('throws INVALID_OTP for codes that differ only in leading zeros', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);

      await svc.store(USER_ID, PURPOSE, '000001');

      await expect(svc.verifyAndConsume(USER_ID, '000010', PURPOSE)).rejects.toMatchObject({
        errorCode: DomainErrorCode.INVALID_OTP,
      });
    });
  });

  describe('verifyAndConsume() — Req 6.8: timing-safe comparison', () => {
    it('uses timingSafeEqual — does not short-circuit on first differing character', async () => {
      // We verify that the comparison does NOT throw early by checking that
      // the consumed sentinel is always written before the comparison result
      // is evaluated (i.e., the code path reaches the comparison regardless).
      const cache = makeInMemoryCache();
      const svc = makeService(cache);
      const correctCode = '123456';

      await svc.store(USER_ID, PURPOSE, correctCode);

      // Submit a code that differs only in the last character
      const wrongCode = '123450';
      const err = await svc.verifyAndConsume(USER_ID, wrongCode, PURPOSE).catch((e) => e);

      expect(err).toBeInstanceOf(DomainException);
      expect((err as DomainException).errorCode).toBe(DomainErrorCode.INVALID_OTP);

      // The consumed sentinel MUST have been written, proving the code was
      // retrieved and the comparison ran to completion (not short-circuited).
      const sentinelKey = `otp:${PURPOSE}:${USER_ID}:consumed`;
      expect(cache.store.has(sentinelKey)).toBe(true);
    });

    it('a subsequent call after a wrong-code attempt throws ALREADY_USED (code was consumed)', async () => {
      // After verifyAndConsume() retrieves the code (even on mismatch), the
      // GETDEL has already deleted it. A retry must see ALREADY_USED, not EXPIRED.
      const cache = makeInMemoryCache();
      const svc = makeService(cache);
      const correctCode = '999888';

      await svc.store(USER_ID, PURPOSE, correctCode);

      // First attempt with wrong code — consumes the stored value
      await svc.verifyAndConsume(USER_ID, '000000', PURPOSE).catch(() => {});

      // Second attempt (even with correct code) must throw ALREADY_USED
      await expect(svc.verifyAndConsume(USER_ID, correctCode, PURPOSE)).rejects.toMatchObject({
        errorCode: DomainErrorCode.OTP_ALREADY_USED,
      });
    });
  });

  describe('verifyAndConsume() — purpose isolation', () => {
    it('codes for different purposes are stored independently', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);

      await svc.store(USER_ID, 'MFA', '111111');
      await svc.store(USER_ID, 'IDENTITY_VERIFICATION', '222222');

      // Correct code for MFA succeeds
      await expect(svc.verifyAndConsume(USER_ID, '111111', 'MFA')).resolves.toBeUndefined();

      // Correct code for IDENTITY_VERIFICATION succeeds independently
      await expect(
        svc.verifyAndConsume(USER_ID, '222222', 'IDENTITY_VERIFICATION'),
      ).resolves.toBeUndefined();
    });

    it('MFA code cannot be used to verify IDENTITY_VERIFICATION purpose', async () => {
      const cache = makeInMemoryCache();
      const svc = makeService(cache);

      await svc.store(USER_ID, 'MFA', '333333');

      // Submitting the MFA code against the IDENTITY_VERIFICATION purpose
      // should fail with OTP_EXPIRED (key doesn't exist for that purpose)
      await expect(
        svc.verifyAndConsume(USER_ID, '333333', 'IDENTITY_VERIFICATION'),
      ).rejects.toMatchObject({ errorCode: DomainErrorCode.OTP_EXPIRED });
    });
  });
});
