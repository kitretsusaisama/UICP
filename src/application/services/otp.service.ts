import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomInt, timingSafeEqual } from 'crypto';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { ICachePort } from '../ports/driven/i-cache.port';
import { DomainException } from '../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../domain/exceptions/domain-error-codes';

/**
 * OTP delivery purposes.
 */
export type OtpPurpose = 'IDENTITY_VERIFICATION' | 'MFA' | 'PASSWORD_RESET';

/**
 * Application service — one-time password generation, storage, and verification.
 *
 * Implements:
 *   - Req 6.1: cryptographically random 6-digit code, Redis SET with 300s TTL
 *   - Req 6.2: atomic Redis GETDEL for single-use guarantee
 *   - Req 6.3: INVALID_OTP on mismatch
 *   - Req 6.4: ALREADY_USED when code already consumed
 *   - Req 6.5: OTP_EXPIRED when TTL elapsed
 *   - Req 6.8: timing-safe comparison
 */
@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name);
  private readonly ttlS: number;

  constructor(
    private readonly config: ConfigService,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {
    this.ttlS = this.config.get<number>('OTP_TTL_S', 300);
  }

  /**
   * Generate a cryptographically random 6-digit OTP code.
   * Uses crypto.randomInt for uniform distribution (Req 6.1).
   */
  generate(): string {
    // randomInt(0, 1_000_000) → [0, 999999]
    const code = randomInt(0, 1_000_000);
    return code.toString().padStart(6, '0');
  }

  /**
   * Store an OTP code in Redis with a TTL.
   * Key format: otp:{purpose}:{userId}
   *
   * Req 6.1: Redis SET with 300s TTL.
   */
  async store(userId: string, purpose: OtpPurpose, code: string): Promise<void> {
    const key = this.otpKey(userId, purpose);
    await this.cache.set(key, code, this.ttlS);

    this.logger.debug({ userId, purpose }, 'OTP stored');
  }

  /**
   * Atomically consume an OTP code using Redis GETDEL (single-use guarantee).
   *
   * - Returns void on success.
   * - Throws DomainException(INVALID_OTP) when code does not match.
   * - Throws DomainException(ALREADY_USED) when code was already consumed.
   * - Throws DomainException(OTP_EXPIRED) when TTL has elapsed (key missing).
   *
   * Uses timing-safe comparison to prevent timing attacks (Req 6.8).
   *
   * Req 6.2: atomic GETDEL.
   */
  async verifyAndConsume(
    userId: string,
    submittedCode: string,
    purpose: OtpPurpose,
  ): Promise<void> {
    const key = this.otpKey(userId, purpose);

    // Atomic GETDEL — returns the value and deletes the key in one operation.
    // If the key doesn't exist (expired or already consumed), returns null.
    const storedCode = await this.cache.getdel(key);

    if (storedCode === null) {
      // Key missing: either expired or already consumed.
      // We can't distinguish between the two without a secondary marker,
      // so we check a "consumed" sentinel key.
      const consumedKey = `${key}:consumed`;
      const wasConsumed = await this.cache.get(consumedKey);

      if (wasConsumed !== null) {
        throw new DomainException(DomainErrorCode.OTP_ALREADY_USED, 'OTP code has already been used');
      }

      throw new DomainException(DomainErrorCode.OTP_EXPIRED, 'OTP code has expired');
    }

    // Mark as consumed (short TTL sentinel to distinguish ALREADY_USED from EXPIRED)
    const consumedKey = `${key}:consumed`;
    await this.cache.set(consumedKey, '1', 60); // 60s sentinel

    // Timing-safe comparison (Req 6.8)
    const match = this.timingSafeCodeEqual(submittedCode, storedCode);
    if (!match) {
      throw new DomainException(DomainErrorCode.INVALID_OTP, 'Invalid OTP code');
    }
  }

  /**
   * Timing-safe comparison of two OTP code strings.
   * Pads both to the same length before comparing to prevent length-based leaks.
   */
  private timingSafeCodeEqual(a: string, b: string): boolean {
    // Normalize to 6 chars to ensure equal-length buffers
    const padded = (s: string) => s.padEnd(6, '\0').substring(0, 6);
    const bufA = Buffer.from(padded(a), 'utf8');
    const bufB = Buffer.from(padded(b), 'utf8');
    return timingSafeEqual(bufA, bufB);
  }

  private otpKey(userId: string, purpose: OtpPurpose): string {
    return `otp:${purpose}:${userId}`;
  }
}
