import { Injectable, Inject, Logger } from '@nestjs/common';
import { ICachePort } from '../../application/ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';

export const OAUTH_CACHE = 'OAUTH_CACHE';

export interface AuthorizationCodeData {
  code: string;
  clientId: string;
  userId: string;
  tenantId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  nonce?: string;
  scopes: string[];
  expiresAt: number;
}

export interface IOAuthCache {
  storeAuthorizationCode(data: AuthorizationCodeData): Promise<void>;
  consumeAuthorizationCode(code: string): Promise<AuthorizationCodeData | null>;
}

@Injectable()
export class RedisOAuthAdapter implements IOAuthCache {
  private readonly logger = new Logger(RedisOAuthAdapter.name);

  constructor(@Inject(INJECTION_TOKENS.CACHE_PORT) private readonly cache: ICachePort) {}

  async storeAuthorizationCode(data: AuthorizationCodeData): Promise<void> {
    const key = `oauth:code:${data.code}`;
    const ttl = Math.max(1, Math.floor((data.expiresAt - Date.now()) / 1000));

    await this.cache.set(key, JSON.stringify(data), ttl);
    this.logger.debug({ code: data.code, clientId: data.clientId }, 'Stored authorization code');
  }

  async consumeAuthorizationCode(code: string): Promise<AuthorizationCodeData | null> {
    const key = `oauth:code:${code}`;

    // Use the native getdel from the cache port for atomicity
    const result = await this.cache.getdel(key);

    if (!result) {
      return null;
    }

    try {
      return JSON.parse(result) as AuthorizationCodeData;
    } catch (e) {
      this.logger.error({ code }, 'Failed to parse authorization code data from Redis');
      return null;
    }
  }
}
