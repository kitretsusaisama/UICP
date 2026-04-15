import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { timingSafeEqual } from 'crypto';
import { Credential } from '../../domain/entities/credential.entity';
import { RawPassword } from '../../domain/value-objects/raw-password.vo';

/**
 * Application service — password hashing and verification.
 *
 * Implements:
 *   - Req 2.9: bcrypt with adaptive rounds + secret pepper
 *   - Req 3.9: async background rehash when rounds change
 *   - Timing-safe comparison to prevent timing attacks
 */
@Injectable()
export class CredentialService {
  private readonly logger = new Logger(CredentialService.name);
  private readonly rounds: number;
  private readonly pepper: string;

  constructor(private readonly config: ConfigService) {
    this.rounds = parseInt(String(this.config.get<number>('BCRYPT_ROUNDS', 12)), 10);
    this.pepper = this.config.getOrThrow<string>('PASSWORD_PEPPER');
  }

  /**
   * Hash a raw password using bcrypt with adaptive rounds and a secret pepper.
   * The pepper is appended to the password before hashing so that a DB breach
   * alone is insufficient to crack credentials.
   *
   * Req 2.9: bcrypt with adaptive Bcrypt_Rounds + pepper.
   */
  async hash(rawPassword: RawPassword): Promise<Credential> {
    const pepperedInput = rawPassword.getValue() + this.pepper;
    const hash = await bcrypt.hash(pepperedInput, this.rounds);

    return new Credential({
      hash,
      algorithm: 'bcrypt',
      rounds: this.rounds,
    });
  }

  /**
   * Verify a raw password against a stored credential using timing-safe comparison.
   *
   * bcrypt.compare is inherently timing-safe for the hash comparison, but we
   * additionally guard the "credential not found" path with a dummy compare
   * to prevent user-enumeration via timing differences.
   *
   * Returns true when the password matches.
   */
  async verify(rawPassword: RawPassword, credential: Credential): Promise<boolean> {
    const pepperedInput = rawPassword.getValue() + this.pepper;
    return bcrypt.compare(pepperedInput, credential.hash);
  }

  /**
   * Perform a timing-safe null check — used when no credential exists for a user
   * to prevent user enumeration via timing attacks (Req 3.8).
   *
   * Runs a dummy bcrypt compare against a fixed hash so the response time is
   * indistinguishable from a real credential check.
   */
  async dummyVerify(): Promise<void> {
    // Pre-computed bcrypt hash of a dummy value — just burns CPU time
    const dummyHash = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.s5uO9G';
    await bcrypt.compare('dummy_timing_safe_check', dummyHash);
  }

  /**
   * Rehash a password with the current rounds (for async background rehash).
   * Called after a successful login when `needsRehash()` returns true.
   *
   * Req 3.9: async background rehash when bcrypt rounds change.
   */
  async rehash(rawPassword: RawPassword): Promise<Credential> {
    return this.hash(rawPassword);
  }

  /**
   * Check whether a credential needs rehashing because the stored rounds differ
   * from the current target rounds.
   */
  needsRehash(credential: Credential): boolean {
    return credential.needsRehash(this.rounds);
  }

  /**
   * Timing-safe string comparison using Node's crypto.timingSafeEqual.
   * Both inputs are converted to Buffers of equal length before comparison.
   */
  timingSafeStringEqual(a: string, b: string): boolean {
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');

    // Buffers must be the same length for timingSafeEqual
    if (bufA.length !== bufB.length) {
      // Still do the comparison to avoid early-exit timing leak, then return false
      timingSafeEqual(bufA, bufA);
      return false;
    }

    return timingSafeEqual(bufA, bufB);
  }

  getCurrentRounds(): number {
    return this.rounds;
  }
}
