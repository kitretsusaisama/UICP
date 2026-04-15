import * as fc from 'fast-check';
import { CredentialService } from './credential.service';
import { RawPassword } from '../../domain/value-objects/raw-password.vo';
import { ConfigService } from '@nestjs/config';

/**
 * Property-based tests for CredentialService.
 *
 * Property 17: verify(p, hash(p, pepper), pepper) = true
 *              verify(p, hash(p, pepper), wrong_pepper) = false
 *
 * Validates: Req 2.9 — bcrypt with adaptive rounds + secret pepper
 */

/** Builds a CredentialService with a given pepper injected via a mock ConfigService. */
function makeService(pepper: string, rounds = 4): CredentialService {
  const config = {
    get: (key: string, defaultValue?: unknown) => {
      if (key === 'BCRYPT_ROUNDS') return rounds;
      return defaultValue;
    },
    getOrThrow: (key: string) => {
      if (key === 'PASSWORD_PEPPER') return pepper;
      throw new Error(`Unknown config key: ${key}`);
    },
  } as unknown as ConfigService;

  return new CredentialService(config);
}

/**
 * Arbitrary that generates valid passwords satisfying all RawPassword invariants:
 * - 10–128 chars
 * - ≥1 uppercase, ≥1 lowercase, ≥1 digit, ≥1 special char
 * - Not in the common-passwords blocklist
 */
const validPasswordArbitrary = fc
  .tuple(
    fc.stringMatching(/[A-Z]/),          // at least one uppercase
    fc.stringMatching(/[a-z]/),          // at least one lowercase
    fc.stringMatching(/[0-9]/),          // at least one digit
    fc.constantFrom('!', '@', '#', '$', '%', '^', '&', '*'),  // special char
    fc.string({ minLength: 4, maxLength: 60, unit: 'grapheme-ascii' }),
  )
  .map(([upper, lower, digit, special, rest]) => {
    // Combine required chars + filler, then shuffle deterministically
    const combined = (upper + lower + digit + special + rest)
      .split('')
      .sort(() => 0.5 - Math.sin(upper.charCodeAt(0) + lower.charCodeAt(0)))
      .join('');
    // Ensure length bounds
    return combined.slice(0, 128).padEnd(10, 'aB1!');
  })
  .filter((p) => {
    try {
      RawPassword.create(p);
      return true;
    } catch {
      return false;
    }
  });

/** Arbitrary that generates non-empty pepper strings */
const pepperArbitrary = fc.string({ minLength: 8, maxLength: 64, unit: 'grapheme-ascii' });

describe('CredentialService — Property 17: pepper consistency', () => {
  /**
   * Property 17a: hash+verify roundtrip with the SAME pepper always succeeds.
   * verify(p, hash(p, pepper), pepper) === true
   */
  it('Property 17a: verify(p, hash(p, pepper), pepper) = true for all valid passwords and peppers', async () => {
    await fc.assert(
      fc.asyncProperty(validPasswordArbitrary, pepperArbitrary, async (rawPw, pepper) => {
        const svc = makeService(pepper);
        const password = RawPassword.create(rawPw);

        const credential = await svc.hash(password);
        const result = await svc.verify(password, credential);

        expect(result).toBe(true);
      }),
      { numRuns: 10, timeout: 30_000 },
    );
  });

  /**
   * Property 17b: verify with a DIFFERENT pepper always fails.
   * verify(p, hash(p, pepper), wrong_pepper) === false
   */
  it('Property 17b: verify(p, hash(p, pepper), wrong_pepper) = false for all valid passwords and distinct peppers', async () => {
    await fc.assert(
      fc.asyncProperty(
        validPasswordArbitrary,
        pepperArbitrary,
        pepperArbitrary,
        async (rawPw, pepper, wrongPepper) => {
          // Ensure the two peppers are actually different
          fc.pre(pepper !== wrongPepper);

          const hashSvc = makeService(pepper);
          const verifySvc = makeService(wrongPepper);
          const password = RawPassword.create(rawPw);

          const credential = await hashSvc.hash(password);
          const result = await verifySvc.verify(password, credential);

          expect(result).toBe(false);
        },
      ),
      { numRuns: 10, timeout: 30_000 },
    );
  });
});
