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
import { parseApiKey, verifySignature } from '../../../shared/utils/api-key-parser';

/**
 * UnifiedAuthGuard — Multi-method authentication guard supporting:
 * - JWT (access tokens with RS256)
 * - API Keys (uF/pB/sF/tB ULID-based format)
 * - Internal Service Auth (X-Internal-Service-Token)
 * - Session-based auth (X-Session-Token)
 *
 * Implements: Req 1.6, Req 7.7
 *
 * Behaviour:
 *  1. Auto-detects authentication method from headers.
 *  2. JWT: Verifies RS256 signature, exp/iss/aud claims, checks blocklist.
 *  3. API Keys (v1): Validates uF/pB/sF/tB prefix format, HMAC signature, rate limits.
 *  4. Internal Service: Validates service-to-service tokens.
 *  5. Session: Validates session tokens from header.
 */
export enum AuthMethod {
  JWT = 'jwt',
  API_KEY = 'api_key',
  INTERNAL_SERVICE = 'internal_service',
  SESSION = 'session',
  NONE = 'none',
}

export const AUTH_METHOD_METADATA = 'auth_method';

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

    const authMethod = this.detectAuthMethod(req);
    req['authMethod'] = authMethod;

    switch (authMethod) {
      case AuthMethod.JWT:
        return await this.authenticateJwt(req);
      case AuthMethod.API_KEY:
        return await this.authenticateApiKey(req);
      case AuthMethod.INTERNAL_SERVICE:
        return await this.authenticateInternalService(req);
      case AuthMethod.SESSION:
        return await this.authenticateSession(req);
      default:
        throw new UnauthorizedException({
          error: { code: 'MISSING_AUTH', message: 'No valid authentication method found' },
        });
    }
  }

  private detectAuthMethod(req: Record<string, unknown>): AuthMethod {
    const headers = req.headers as Record<string, string | string[] | undefined>;
    const authHeader = typeof headers?.['authorization'] === 'string' ? headers['authorization'] : Array.isArray(headers?.['authorization']) ? headers['authorization'][0] : undefined;
    const apiKeyHeader = typeof headers?.['x-api-key'] === 'string' ? headers['x-api-key'] : Array.isArray(headers?.['x-api-key']) ? headers['x-api-key'][0] : undefined;
    const internalToken = typeof headers?.['x-internal-service-token'] === 'string' ? headers['x-internal-service-token'] : Array.isArray(headers?.['x-internal-service-token']) ? headers['x-internal-service-token'][0] : undefined;
    const sessionToken = typeof headers?.['x-session-token'] === 'string' ? headers['x-session-token'] : Array.isArray(headers?.['x-session-token']) ? headers['x-session-token'][0] : undefined;

    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      // Check for v1 API key format: uF/pB/sF/tB prefix
      if (token.startsWith('uF') || token.startsWith('pB') || token.startsWith('sF') || token.startsWith('tB')) {
        return AuthMethod.API_KEY;
      }
      return AuthMethod.JWT;
    }

    if (apiKeyHeader) {
      return AuthMethod.API_KEY;
    }

    if (internalToken) return AuthMethod.INTERNAL_SERVICE;
    if (sessionToken) return AuthMethod.SESSION;

    return AuthMethod.NONE;
  }

  private async authenticateJwt(req: Record<string, unknown>): Promise<boolean> {
    const headers = req.headers as Record<string, string | string[] | undefined>;
    const authHeader = typeof headers?.['authorization'] === 'string' ? headers['authorization'] : Array.isArray(headers?.['authorization']) ? headers['authorization'][0] : undefined;
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

    const blocklisted = await this.cache.sismember('jwt:blocklist', payload.jti);
    if (blocklisted) {
      throw new UnauthorizedException({
        error: { code: 'TOKEN_REVOKED', message: 'Token has been revoked' },
      });
    }

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
    req['authMethod'] = AuthMethod.JWT;

    return true;
  }

  private async authenticateApiKey(req: Record<string, unknown>): Promise<boolean> {
    const headers = req.headers as Record<string, string | string[] | undefined>;
    const authHeader = typeof headers?.['authorization'] === 'string' ? headers['authorization'] : Array.isArray(headers?.['authorization']) ? headers['authorization'][0] : undefined;
    const apiKeyHeader = typeof headers?.['x-api-key'] === 'string' ? headers['x-api-key'] : Array.isArray(headers?.['x-api-key']) ? headers['x-api-key'][0] : undefined;
    const apiKey = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : apiKeyHeader;

    if (!apiKey) {
      throw new UnauthorizedException({
        error: { code: 'MISSING_API_KEY', message: 'API key is required' },
      });
    }

    const parsed = parseApiKey(apiKey);
    if (!parsed) {
      throw new UnauthorizedException({
        error: { code: 'INVALID_API_KEY', message: 'Invalid API key format' },
      });
    }

    if (parsed.signature) {
      const hmacSecret = process.env.API_KEY_HMAC_SECRET;
      if (!hmacSecret) {
        throw new Error('CRITICAL: API_KEY_HMAC_SECRET environment variable is not set');
      }
      const isValid = verifySignature(apiKey, hmacSecret, 'default-tenant');
      if (!isValid) {
        throw new UnauthorizedException({
          error: { code: 'INVALID_SIGNATURE', message: 'API key signature verification failed' },
        });
      }
    }

    const keyId = parsed.ulid;
    const rateLimitKey = `ratelimit:api_key:${keyId}`;
    const currentCount = await this.cache.get(rateLimitKey) || '0';
    const limit = 1000;

    if (parseInt(currentCount, 10) >= limit) {
      throw new UnauthorizedException({
        error: { code: 'RATE_LIMIT_EXCEEDED', message: 'API key rate limit exceeded' },
      });
    }

    await this.cache.set(rateLimitKey, (parseInt(currentCount, 10) + 1).toString(), 60);

    req['apiKeyId'] = keyId;
    req['apiKeyUlid'] = keyId;
    req['apiKeyType'] = parsed.type;
    req['authMethod'] = AuthMethod.API_KEY;

    return true;
  }

  private async authenticateInternalService(req: Record<string, unknown>): Promise<boolean> {
    const headers = req.headers as Record<string, string | string[] | undefined>;
    const internalToken = typeof headers?.['x-internal-service-token'] === 'string' ? headers['x-internal-service-token'] : Array.isArray(headers?.['x-internal-service-token']) ? headers['x-internal-service-token'][0] : undefined;

    if (!internalToken) {
      throw new UnauthorizedException({
        error: { code: 'MISSING_INTERNAL_TOKEN', message: 'Internal service token is required' },
      });
    }

    const validTokens = (process.env.INTERNAL_SERVICE_TOKENS || '').split(',').filter(Boolean);
    if (!validTokens.includes(internalToken)) {
      throw new UnauthorizedException({
        error: { code: 'INVALID_INTERNAL_TOKEN', message: 'Invalid internal service token' },
      });
    }

    req['serviceId'] = internalToken.split(':')[0] || 'internal';
    req['authMethod'] = AuthMethod.INTERNAL_SERVICE;
    req['isInternalService'] = true;

    return true;
  }

  private async authenticateSession(req: Record<string, unknown>): Promise<boolean> {
    const headers = req.headers as Record<string, string | string[] | undefined>;
    const sessionToken = typeof headers?.['x-session-token'] === 'string' ? headers['x-session-token'] : Array.isArray(headers?.['x-session-token']) ? headers['x-session-token'][0] : undefined;

    if (!sessionToken) {
      throw new UnauthorizedException({
        error: { code: 'MISSING_SESSION_TOKEN', message: 'Session token is required' },
      });
    }

    const sessionData = await this.cache.get(`session:${sessionToken}`);
    if (!sessionData) {
      throw new UnauthorizedException({
        error: { code: 'INVALID_SESSION', message: 'Session expired or invalid' },
      });
    }

    const session = JSON.parse(sessionData);
    req['sessionId'] = sessionToken;
    req['userId'] = session.userId;
    req['tenantId'] = session.tenantId;
    req['authMethod'] = AuthMethod.SESSION;

    return true;
  }
}
