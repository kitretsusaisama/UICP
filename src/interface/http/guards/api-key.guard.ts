import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { parseApiKey, verifySignature } from '../../../shared/utils/api-key-parser';
import { ApiKeyService } from '../../../application/services/api-key.service';

export const API_KEY_METADATA = 'api_key';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly apiKeyService: ApiKeyService,
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

    const keyEntity = await this.apiKeyService.getByUlid(parsed.ulid);

    if (!keyEntity || !keyEntity.isActive) {
      throw new UnauthorizedException('API key not found or inactive');
    }

    if (parsed.signature) {
      const isValid = verifySignature(
        apiKey,
        process.env.API_KEY_HMAC_SECRET || 'default-secret',
        keyEntity.tenantId
      );
      if (!isValid) {
        throw new UnauthorizedException('Invalid API key signature');
      }
    }

    const clientIp = request.ip || request.connection?.remoteAddress;
    if (keyEntity.ipAllowlist.length > 0 && clientIp) {
      const isAllowed = keyEntity.ipAllowlist.some(cidr => this.cidrMatch(clientIp, cidr));
      if (!isAllowed) {
        throw new UnauthorizedException('IP not allowed');
      }
    }

    request.apiKey = keyEntity;
    request.tenantId = keyEntity.tenantId;
    return true;
  }

  private cidrMatch(ip: string, cidr: string): boolean {
    const parts = cidr.split('/');
    if (parts.length !== 2) return ip === cidr;
    const range = parts[0];
    const bitsStr = parts[1];
    if (!range || !bitsStr) return false;
    const bits = parseInt(bitsStr, 10);
    if (isNaN(bits) || bits < 0 || bits > 32) return false;
    const mask = ~(2 ** (32 - bits) - 1);
    const ipInt = this.ipToInt(ip);
    const rangeInt = this.ipToInt(range);
    return (ipInt & mask) === (rangeInt & mask);
  }

  private ipToInt(ip: string): number {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  }
}
