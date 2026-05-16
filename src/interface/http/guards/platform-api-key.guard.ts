import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { parseApiKey, verifySignature } from '../../../shared/utils/api-key-parser';
import { PlatformApiKeyService } from '../../../application/services/platform/platform-api-key.service';
import { PlatformIdentityService } from '../../../application/services/platform/platform-identity.service';

export const PLATFORM_API_KEY_METADATA = 'platform_api_key';
export const PLATFORM_SCOPES_METADATA = 'platform_scopes';

@Injectable()
export class PlatformApiKeyGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly platformApiKeyService: PlatformApiKeyService,
    private readonly platformIdentityService: PlatformIdentityService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or invalid Authorization header');
    }

    const apiKey = authHeader.substring(7);
    const parsed = parseApiKey(apiKey);

    if (!parsed) {
      throw new UnauthorizedException('Invalid API key format');
    }

    const keyEntity = await this.platformApiKeyService.getByUlid(parsed.ulid);

    if (!keyEntity || !keyEntity.isActive) {
      throw new UnauthorizedException('API key not found or inactive');
    }

    if (parsed.signature) {
      const hmacSecret = process.env.PLATFORM_API_KEY_HMAC_SECRET || process.env.API_KEY_HMAC_SECRET;
      if (!hmacSecret) {
        throw new Error('CRITICAL: PLATFORM_API_KEY_HMAC_SECRET or API_KEY_HMAC_SECRET environment variable is not set');
      }
      const isValid = verifySignature(
        apiKey,
        hmacSecret,
        keyEntity.platformIdentityId
      );
      if (!isValid) {
        throw new UnauthorizedException('Invalid API key signature');
      }
    }

    const requiredScopes = this.reflector.get<string[]>(PLATFORM_SCOPES_METADATA, context.getHandler());
    if (requiredScopes && Array.isArray(requiredScopes) && requiredScopes.length > 0) {
      const hasRequiredScope = requiredScopes.some((scope: string) => keyEntity.hasScope(scope));
      if (!hasRequiredScope) {
        throw new ForbiddenException(`Missing required scope(s): ${requiredScopes.join(', ')}`);
      }
    }

    const identity = await this.platformIdentityService.getById(keyEntity.platformIdentityId);

    if (!identity || !identity.isActive) {
      throw new ForbiddenException('Platform identity is not active');
    }

    if (identity.requiresStepUp) {
      request.stepUpRequired = true;
      request.stepUpReason = `Risk score ${identity.riskScore} exceeds threshold`;
    }

    const clientIp = request.ip || request.connection?.remoteAddress;
    await this.platformApiKeyService.recordUsage(keyEntity.id, clientIp);

    request.platformApiKey = keyEntity;
    request.platformIdentity = identity;
    request.platformId = keyEntity.platformIdentityId;

    return true;
  }
}