import { Injectable } from '@nestjs/common';
import { ValidateTokenQuery } from './validate-token.query';
import { TokenService, AccessTokenPayload } from '../../services/token.service';
import { UicpLogger } from '../../../shared/logger/pino-logger.service';
import { measure } from '../../../shared/logger/measure';

export interface TokenClaimsDto {
  sub: string;
  jti: string;
  tid: string;
  mid: string;
  aid: string;
  sid: string;
  pv: string;
  mv: string;
  capabilities: string[];
  roles: string[];
  perms: string[];
  mfa: boolean;
  amr: string[];
  acr: string;
  iat: number;
  exp: number;
}

/**
 * Query handler — validate an access token with zero DB round trips.
 *
 * Implements: Req 7.7:
 *   - Verify RS256 signature
 *   - Check `exp` claim (handled by jsonwebtoken)
 *   - Verify `iss` and `aud` claims (handled by jsonwebtoken)
 *   - O(1) Redis blocklist check via ZSCORE (no DB)
 *
 * Throws on any validation failure (invalid signature, expired, blocklisted).
 */
@Injectable()
export class ValidateTokenHandler {
  constructor(
    private readonly tokenService: TokenService,
    private readonly logger: UicpLogger,
  ) {}

  async handle(query: ValidateTokenQuery): Promise<TokenClaimsDto> {
    return measure(
      { logger: this.logger, operation: 'token_validation', context: ValidateTokenHandler.name },
      async () => {
        const payload: AccessTokenPayload = await this.tokenService.validateAccessToken(query.token);
        return {
          sub: payload.sub,
          jti: payload.jti,
          tid: payload.tid,
          mid: payload.mid,
          aid: payload.aid,
          sid: payload.sid,
          pv: payload.pv,
          mv: payload.mv,
          capabilities: payload.capabilities ?? [],
          roles: payload.roles ?? [],
          perms: payload.perms ?? [],
          mfa: payload.mfa ?? false,
          amr: payload.amr,
          acr: payload.acr,
          iat: payload.iat,
          exp: payload.exp,
        };
      },
    );
  }
}
