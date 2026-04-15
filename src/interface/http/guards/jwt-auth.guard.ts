import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { TokenService } from '../../../application/services/token.service';

/**
 * JwtAuthGuard — verifies RS256 access tokens and populates request context.
 *
 * Implements: Req 1.6, Req 7.7
 *
 * Behaviour:
 *  1. Extracts Bearer token from Authorization header.
 *  2. Verifies RS256 signature, `exp`, `iss`, `aud` claims via TokenService.
 *  3. Checks `jti` against Redis blocklist via ICachePort.
 *  4. Sets principal, membership, actor, and transitional legacy claims on request.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);

  constructor(
    private readonly tokenService: TokenService,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Record<string, unknown> & { headers: Record<string, string | string[] | undefined> }>();

    const authHeader = req.headers['authorization'] as string | undefined;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException({
        error: { code: 'MISSING_TOKEN', message: 'Authorization Bearer token is required' },
      });
    }

    const token = authHeader.slice(7);

    let payload;
    try {
      payload = this.tokenService.parseAccessToken(token);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Invalid token';
      this.logger.warn({ message }, 'JWT verification failed');
      throw new UnauthorizedException({
        error: { code: 'INVALID_TOKEN', message },
      });
    }

    // Check blocklist via Redis
    const blocklisted = await this.cache.sismember('jwt:blocklist', payload.jti);
    if (blocklisted) {
      throw new UnauthorizedException({
        error: { code: 'TOKEN_REVOKED', message: 'Token has been revoked' },
      });
    }

    // Populate request context for downstream guards and handlers
    req['principalId'] = payload.sub;
    req['userId'] = payload.sub;
    req['membershipId'] = payload.mid;
    req['actorId'] = payload.aid;
    req['sessionId'] = payload.sid;
    req['policyVersion'] = payload.pv;
    req['manifestVersion'] = payload.mv;
    req['capabilities'] = payload.capabilities ?? [];
    req['roles'] = payload.roles ?? [];
    req['perms'] = payload.perms ?? [];
    req['jwtTid'] = payload.tid;
    req['tenantId'] = payload.tid;
    req['acr'] = payload.acr;
    req['jti'] = payload.jti;

    return true;
  }
}
