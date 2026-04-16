import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import { Session } from '../../domain/aggregates/session.aggregate';
import { UserId } from '../../domain/value-objects/user-id.vo';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { ITokenRepository } from '../ports/driven/i-token.repository';

/**
 * Access token JWT payload (Section 8.1).
 */
export interface AccessTokenPayload {
  iss: string;
  aud: string | string[];
  sub: string;
  iat: number;
  exp: number;
  jti: string;
  tid: string;
  mid: string;
  aid: string;
  sid: string;
  pv: string;
  mv: string;
  type: 'access';
  capabilities: string[];
  roles?: string[];
  perms?: string[];
  mfa?: boolean;
  vat?: number;
  amr: string[];
  acr: string;
  dfp?: string;
}

/**
 * Refresh token JWT payload (Section 8.2).
 */
export interface RefreshTokenPayload {
  iss: string;
  aud: string;
  sub: string;
  iat: number;
  exp: number;
  jti: string;
  tid: string;
  fid: string;
  mid?: string;
  sid?: string;
  type: 'refresh';
}

export interface MintedTokens {
  accessToken: string;
  refreshToken: string;
  accessTokenJti: string;
  refreshTokenJti: string;
  familyId: string;
  accessExpiresAt: Date;
  refreshExpiresAt: Date;
}

/**
 * Application service — JWT token lifecycle management.
 *
 * Implements:
 *   - Req 7.1: RS256 access token with 15-min TTL, embedded roles/perms/mfa/amr
 *   - Req 7.2: RS256 refresh token with 7-day TTL and fid claim
 *   - Req 7.3: token rotation (parse + re-mint)
 *   - Req 7.5: blocklist via ITokenRepository
 *   - Req 7.7: validate access token (signature + exp + iss/aud + blocklist)
 *   - Req 7.8/7.9: key rotation support via kid header
 */
@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);

  private readonly privateKey: string;
  private readonly publicKey: string;
  private readonly kid: string;
  private readonly issuer: string;
  private readonly audience: string;
  private readonly accessTtlS: number;
  private readonly refreshTtlS: number;

  constructor(
    private readonly config: ConfigService,
    @Inject(INJECTION_TOKENS.TOKEN_REPOSITORY)
    private readonly tokenRepo: ITokenRepository,
  ) {
    // WAR-GRADE DEFENSE: Phase 6 Security Hard Reset (Secrets Management)
    // The private key must not reside in memory during normal operations.
    // In a real environment, JWT signing must be delegated to a KMS (e.g. AWS KMS, Vault).
    // Here we simulate an isolated KMS boundary by enforcing the API contract.
    const rawKey = this.config.get<string>('JWT_PRIVATE_KEY');
    const encKey = this.config.get<string>('JWT_PRIVATE_KEY_ENC');
    if (!rawKey && !encKey) {
      throw new Error('JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_ENC must be set');
    }

    // Retained strictly to conform to the existing local jsonwebtoken sign logic constraint in this mock.
    // In a fully rewritten Rust edge auth, this class only dispatches `SignRequest` to the KMS port.
    this.privateKey = (rawKey ?? encKey!).replace(/\\n/g, '\n');

    this.publicKey = this.config.getOrThrow<string>('JWT_PUBLIC_KEY').replace(/\\n/g, '\n');
    this.kid = this.config.getOrThrow<string>('JWT_KID');
    this.issuer = this.config.getOrThrow<string>('JWT_ISSUER');
    this.audience = this.config.getOrThrow<string>('JWT_AUDIENCE');
    this.accessTtlS = this.config.get<number>('JWT_ACCESS_TOKEN_TTL_S', 900);
    this.refreshTtlS = this.config.get<number>('JWT_REFRESH_TOKEN_TTL_S', 604800);
  }

  // KMS Sign abstraction layer for War-Grade security
  private async kmsSign(payload: object, kid: string): Promise<string> {
    // Simulated remote KMS call.
    // In production: await awsKmsClient.sign({ Message: payload, KeyId: kid, SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256' });
    return jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256',
      keyid: kid,
      noTimestamp: true,
    });
  }

  /**
   * Mint an RS256 access token for a user + session pair.
   * Embeds roles, perms, mfa, and amr claims so downstream services can
   * authorize without a DB call (Req 7.1).
   */
  async mintAccessToken(input: {
    principalId: string;
    tenantId: string;
    membershipId: string;
    actorId: string;
    session: Session;
    capabilities?: string[];
    roles?: string[];
    perms?: string[];
    amr: string[];
    policyVersion?: string;
    manifestVersion?: string;
    authAssuranceLevel?: string;
  }): Promise<{ token: string; jti: string; expiresAt: Date }> {
    const now = Math.floor(Date.now() / 1000);
    const jti = randomUUID();
    const expiresAt = new Date((now + this.accessTtlS) * 1000);

    const payload: AccessTokenPayload = {
      iss: this.issuer,
      aud: this.audience,
      sub: input.principalId,
      iat: now,
      exp: now + this.accessTtlS,
      jti,
      tid: input.tenantId,
      mid: input.membershipId,
      aid: input.actorId,
      sid: input.session.id.toString(),
      pv: input.policyVersion ?? input.session.policyVersion ?? 'legacy-policy-v1',
      mv: input.manifestVersion ?? input.session.manifestVersion ?? 'legacy-manifest-v1',
      type: 'access',
      capabilities: input.capabilities ?? [],
      roles: input.roles,
      perms: input.perms,
      mfa: input.session.isMfaVerified(),
      vat: input.session.getMfaVerifiedAt()
        ? Math.floor(input.session.getMfaVerifiedAt()!.getTime() / 1000)
        : undefined,
      amr: input.amr,
      acr: input.authAssuranceLevel ?? (input.session.isMfaVerified() ? 'aal2' : 'aal1'),
      dfp: input.session.deviceFingerprint?.substring(0, 8),
    };

    const token = await this.kmsSign(payload, this.kid);

    return { token, jti, expiresAt };
  }

  /**
   * Mint an RS256 refresh token.
   * Carries a family ID (fid) for reuse-detection revocation (Req 7.2).
   */
  async mintRefreshToken(
    userId: UserId,
    tenantId: TenantId,
    familyId: string,
    membershipId?: string,
    sessionId?: string,
  ): Promise<{ token: string; jti: string; expiresAt: Date }> {
    const now = Math.floor(Date.now() / 1000);
    const jti = randomUUID();
    const expiresAt = new Date((now + this.refreshTtlS) * 1000);

    const payload: RefreshTokenPayload = {
      iss: this.issuer,
      aud: `${this.issuer}/refresh`,
      sub: userId.toString(),
      iat: now,
      exp: now + this.refreshTtlS,
      jti,
      tid: tenantId.toString(),
      fid: familyId,
      mid: membershipId,
      sid: sessionId,
      type: 'refresh',
    };

    const token = await this.kmsSign(payload, this.kid);

    return { token, jti, expiresAt };
  }

  /**
   * Parse and verify a refresh token.
   * Validates RS256 signature, exp, iss, aud, and type claim.
   *
   * @throws JsonWebTokenError on invalid signature or expired token.
   */
  parseRefreshToken(token: string): RefreshTokenPayload {
    const payload = jwt.verify(token, this.publicKey, {
      algorithms: ['RS256'],
      issuer: this.issuer,
      audience: `${this.issuer}/refresh`,
    }) as RefreshTokenPayload;

    if (payload.type !== 'refresh') {
      throw new Error('TOKEN_TYPE_MISMATCH: expected refresh token');
    }

    return payload;
  }

  /**
   * Parse and verify an access token.
   * Validates RS256 signature, exp, iss, aud, and type claim.
   * Does NOT check the blocklist — callers must do that separately (Req 7.7).
   *
   * @throws JsonWebTokenError on invalid signature or expired token.
   */
  parseAccessToken(token: string): AccessTokenPayload {
    const payload = jwt.verify(token, this.publicKey, {
      algorithms: ['RS256'],
      issuer: this.issuer,
      audience: this.audience,
    }) as AccessTokenPayload;

    if (payload.type !== 'access') {
      throw new Error('TOKEN_TYPE_MISMATCH: expected access token');
    }

    return payload;
  }

  /**
   * Validate an access token fully: signature + exp + iss/aud + blocklist check.
   * Zero DB round trips — blocklist is O(1) Redis ZSCORE (Req 7.7).
   *
   * Returns the parsed payload when valid, throws otherwise.
   */
  async validateAccessToken(token: string): Promise<AccessTokenPayload> {
    const payload = this.parseAccessToken(token);

    const blocklisted = await this.tokenRepo.isBlocklisted(payload.jti);
    if (blocklisted) {
      throw new Error('TOKEN_BLOCKLISTED: access token has been revoked');
    }

    return payload;
  }

  /**
   * Rotate a signing key: begin signing new tokens with the new key.
   * The old key remains in the JWKS endpoint for the overlap window (Req 7.8/7.9).
   *
   * In practice this updates the in-memory key reference; the actual key
   * persistence is handled by the RotateKeysHandler command.
   */
  rotateSigningKey(newPrivateKey: string, newPublicKey: string, newKid: string): void {
    // Retain old key for 7-day overlap window (Req 7.8)
    const overlapWindowMs = 7 * 24 * 60 * 60 * 1000;
    this._deprecatedKeys.push({
      publicKey: this.publicKey,
      kid: this.kid,
      expiresAt: new Date(Date.now() + overlapWindowMs),
    });

    (this as any).privateKey = newPrivateKey;
    (this as any).publicKey = newPublicKey;
    (this as any).kid = newKid;
    this.logger.log({ newKid }, 'JWT signing key rotated');
  }

  getPublicKey(): string {
    return this.publicKey;
  }

  getKid(): string {
    return this.kid;
  }

  /**
   * Return deprecated public keys still within the 7-day overlap window (Req 7.8).
   * Keys are added here by rotateSigningKey and expire after 7 days.
   */
  getDeprecatedPublicKeys(): Array<{ publicKey: string; kid: string }> {
    return this._deprecatedKeys.filter(
      (k) => k.expiresAt > new Date(),
    );
  }

  private readonly _deprecatedKeys: Array<{
    publicKey: string;
    kid: string;
    expiresAt: Date;
  }> = [];
}
