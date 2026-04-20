import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Inject } from '@nestjs/common';
import { Request } from 'express';
import { IAppSecretRepository } from '../../../../src/domain/repositories/platform/app-secret.repository.interface';
import * as crypto from 'crypto';

@Injectable()
export class ClientBasicAuthGuard implements CanActivate {
  constructor(
    @Inject('APP_SECRET_REPOSITORY') private readonly secretRepo: IAppSecretRepository
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Basic ')) {
      throw new UnauthorizedException('Missing or invalid Authorization header (Basic auth required)');
    }

    let clientId: string;
    let clientSecret: string;

    try {
      const decoded = Buffer.from(authHeader.split(' ')[1], 'base64').toString('utf8');
      const colonIdx = decoded.indexOf(':');
      if (colonIdx === -1) throw new Error('Invalid format');
      clientId = decoded.substring(0, colonIdx);
      clientSecret = decoded.substring(colonIdx + 1);
    } catch (err) {
      throw new UnauthorizedException('Malformed Basic authentication payload');
    }

    const appSecretEntities = await this.secretRepo.findByAppId(clientId);
    if (!appSecretEntities || appSecretEntities.length === 0) {
      throw new UnauthorizedException('Invalid client credentials');
    }

    // AppSecretService.createSecret uses SHA-256 for machine-generated secrets (not bcrypt).
    // Thus we hash the incoming raw secret and do a constant-time check.
    const incomingHash = crypto.createHash('sha256').update(clientSecret).digest('hex');

    // Iterate through active/deprecated keys for graceful rollover
    let matchedApp = null;
    for (const secretEntity of appSecretEntities) {
       if (secretEntity.status !== 'active' && secretEntity.status !== 'deprecated') continue;

       try {
           const isValid = crypto.timingSafeEqual(Buffer.from(incomingHash), Buffer.from(secretEntity.secretHash));
           if (isValid) {
               matchedApp = secretEntity;
               break;
           }
       } catch(e) {
           // Mismatched buffer lengths
       }
    }

    if (!matchedApp) {
      throw new UnauthorizedException('Invalid client credentials');
    }

    // Inject verified app/client into request
    (req as any).clientApp = {
       clientId: matchedApp.appId,
       tenantId: matchedApp.tenantId
    };

    return true;
  }
}
