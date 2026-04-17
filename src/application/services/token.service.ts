import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import { Session } from '../../domain/aggregates/session.aggregate';
import { UserId } from '../../domain/value-objects/user-id.vo';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { ITokenRepository } from '../ports/driven/i-token.repository';

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
    const rawKey = this.config.get<string>('JWT_PRIVATE_KEY');
    const encKey = this.config.get<string>('JWT_PRIVATE_KEY_ENC');
    if (!rawKey && !encKey) {
      throw new Error('JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_ENC must be set');
    }

    this.privateKey = (rawKey ?? encKey!).replace(/\\n/g, '\n');
    this.publicKey = this.config.getOrThrow<string>('JWT_PUBLIC_KEY').replace(/\\n/g, '\n');
    this.kid = this.config.getOrThrow<string>('JWT_KID');
    this.issuer = this.config.getOrThrow<string>('JWT_ISSUER');
    this.audience = this.config.getOrThrow<string>('JWT_AUDIENCE');
    this.accessTtlS = this.config.get<number>('JWT_ACCESS_TOKEN_TTL_S', 900);
    this.refreshTtlS = this.config.get<number>('JWT_REFRESH_TOKEN_TTL_S', 604800);
  }

  private async kmsSign(payload: object, kid: string): Promise<string> {
    return jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256',
      keyid: kid,
      noTimestamp: true,
    });
  }

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

  async mintIdToken(payload: {
    sub: string;
    aud: string;
    nonce?: string;
    auth_time: number;
    acr: string;
  }): Promise<{ token: string; expiresAt: Date }> {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = new Date((now + this.accessTtlS) * 1000);

    const fullPayload = {
      iss: this.issuer,
      iat: now,
      exp: now + this.accessTtlS,
      ...payload,
    };

    const token = await this.kmsSign(fullPayload, this.kid);
    return { token, expiresAt };
  }

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

  async validateAccessToken(token: string): Promise<AccessTokenPayload> {
    const payload = this.parseAccessToken(token);
    const blocklisted = await this.tokenRepo.isBlocklisted(payload.jti);
    if (blocklisted) {
      throw new Error('TOKEN_BLOCKLISTED: access token has been revoked');
    }
    return payload;
  }

  rotateSigningKey(newPrivateKey: string, newPublicKey: string, newKid: string): void {
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
