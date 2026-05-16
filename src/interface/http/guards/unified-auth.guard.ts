import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Inject } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { parseApiKey, verifySignature } from '../../../shared/utils/api-key-parser';
import { TokenService } from '../../../application/services/token.service';
import { ApiKeyService } from '../../../application/services/api-key.service';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';

/**
 * UnifiedAuthGuard - Supports JWT, API Key, Internal Service, Session auth
 * For tenant-level APIs that need flexible authentication options
 */
@Injectable()
export class UnifiedAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly tokenService: TokenService,
    private readonly apiKeyService: ApiKeyService,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Record<string, unknown> & { headers: Record<string, string | string[] | undefined> }>();
    const authHeader = this.getHeader(req, 'authorization');
    const apiKeyHeader = this.getHeader(req, 'x-api-key');
    const internalToken = this.getHeader(req, 'x-internal-service-token');
    const sessionToken = this.getHeader(req, 'x-session-token');

    // Try each auth method in order
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);

      // Check if it's an API key (uF/pB/sF/tB prefix)
      if (token.startsWith('uF') || token.startsWith('pB') || token.startsWith('sF') || token.startsWith('tB')) {
        return await this.authenticateApiKey(req, token);
      }

      // Otherwise treat as JWT
      return await this.authenticateJwt(req, token);
    }

    if (apiKeyHeader) {
      return await this.authenticateApiKey(req, apiKeyHeader);
    }

    if (internalToken) {
      return await this.authenticateInternalService(req, internalToken);
    }

    if (sessionToken) {
      return await this.authenticateSession(req, sessionToken);
    }

    throw new UnauthorizedException({
      error: { code: 'MISSING_AUTH', message: 'No valid authentication method found' },
    });
  }

  private getHeader(req: Record<string, unknown>, name: string): string | undefined {
    const headers = req.headers as Record<string, string | string[] | undefined>;
    const value = headers?.[name];
    return typeof value === 'string' ? value : Array.isArray(value) ? value[0] : undefined;
  }

  private async authenticateJwt(req: Record<string, unknown>, token: string): Promise<boolean> {
    let payload;
    try {
      payload = this.tokenService.parseAccessToken(token);
    } catch {
      throw new UnauthorizedException({
        error: { code: 'INVALID_TOKEN', message: 'Invalid JWT token' },
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
    req['jwtTid'] = payload.tid;
    req['tenantId'] = payload.tid;
    req['roles'] = payload.roles ?? [];
    req['capabilities'] = payload.capabilities ?? [];
    req['authMethod'] = 'jwt';

    return true;
  }

  private async authenticateApiKey(req: Record<string, unknown>, apiKey: string): Promise<boolean> {
    const parsed = parseApiKey(apiKey);
    if (!parsed) {
      throw new UnauthorizedException({
        error: { code: 'INVALID_API_KEY', message: 'Invalid API key format' },
      });
    }

    const validation = await this.apiKeyService.validateKey(parsed.ulid, apiKey);
    if (!validation.isValid || !validation.key) {
      throw new UnauthorizedException({
        error: { code: validation.error?.code ?? 'INVALID_API_KEY', message: validation.error?.message ?? 'API key validation failed' },
      });
    }

    const clientIp = req['ip'] as string | undefined;
    if (clientIp && validation.key.ipAllowlist.length > 0 && !validation.key.isIpAllowed(clientIp)) {
      throw new UnauthorizedException({
        error: { code: 'IP_NOT_ALLOWED', message: 'IP address not allowed' },
      });
    }

    // Set tenant context from API key
    req['apiKey'] = validation.key;
    req['apiKeyId'] = validation.key.ulid;
    req['tenantId'] = validation.key.tenantId;
    req['authMethod'] = 'api_key';

    return true;
  }

  private async authenticateInternalService(req: Record<string, unknown>, token: string): Promise<boolean> {
    const validTokens = (process.env.INTERNAL_SERVICE_TOKENS || '').split(',').filter(Boolean);
    if (!validTokens.includes(token)) {
      throw new UnauthorizedException({
        error: { code: 'INVALID_INTERNAL_TOKEN', message: 'Invalid internal service token' },
      });
    }

    req['serviceId'] = token.split(':')[0] || 'internal';
    req['isInternalService'] = true;
    req['authMethod'] = 'internal_service';

    return true;
  }

  private async authenticateSession(req: Record<string, unknown>, token: string): Promise<boolean> {
    const sessionData = await this.cache.get(`session:${token}`);
    if (!sessionData) {
      throw new UnauthorizedException({
        error: { code: 'INVALID_SESSION', message: 'Session expired or invalid' },
      });
    }

    const session = JSON.parse(sessionData);
    req['sessionId'] = token;
    req['userId'] = session.userId;
    req['tenantId'] = session.tenantId;
    req['authMethod'] = 'session';

    return true;
  }
}