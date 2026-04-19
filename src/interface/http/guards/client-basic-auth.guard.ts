import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Inject } from '@nestjs/common';
import { Request } from 'express';
import { AppSecretRepository } from '../../../../src/domain/repositories/platform/app-secret.repository.interface';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

@Injectable()
export class ClientBasicAuthGuard implements CanActivate {
  constructor(
    @Inject('APP_SECRET_REPOSITORY') private readonly secretRepo: AppSecretRepository
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
      const parts = decoded.split(':');
      if (parts.length !== 2) throw new Error('Invalid format');
      clientId = parts[0];
      clientSecret = parts[1];
    } catch (err) {
      throw new UnauthorizedException('Malformed Basic authentication payload');
    }

    const appSecretEntity = await this.secretRepo.findByAppId(clientId);
    // Allow both active and deprecated secrets during grace period rollover
    if (!appSecretEntity || (appSecretEntity.status !== 'active' && appSecretEntity.status !== 'deprecated')) {
      throw new UnauthorizedException('Invalid client credentials');
    }

    // Hash the incoming plain secret using SHA256 exactly as done during creation in AppSecretService
    const incomingHash = crypto.createHash('sha256').update(clientSecret).digest('hex');

    // Compare against the stored bcrypt hash using constant-time comparison
    const isValid = await bcrypt.compare(incomingHash, appSecretEntity.secretHash);
    if (!isValid) {
      throw new UnauthorizedException('Invalid client credentials');
    }

    // Inject verified app/client into request
    (req as any).clientApp = {
       clientId: appSecretEntity.appId,
       tenantId: appSecretEntity.tenantId
    };

    return true;
  }
}
