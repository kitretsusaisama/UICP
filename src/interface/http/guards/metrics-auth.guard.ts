import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';

@Injectable()
export class MetricsAuthGuard implements CanActivate {
  private readonly allowedIps = process.env.METRICS_ALLOWED_IPS ? process.env.METRICS_ALLOWED_IPS.split(',') : ['127.0.0.1', '::1'];
  private readonly scrapeToken = process.env.METRICS_SCRAPE_TOKEN || 'default-dev-scrape-token-please-change';

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();

    // 1. IP Allowlist verification (Primary Layer)
    const clientIp = request.ip || request.connection.remoteAddress || '';
    const isIpAllowed = this.allowedIps.some(ip => clientIp.includes(ip));

    if (!isIpAllowed) {
       throw new UnauthorizedException('Metrics access denied (IP)');
    }

    // 2. Bearer Token verification (Secondary Layer)
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
       throw new UnauthorizedException('Metrics access denied (Token missing)');
    }

    const token = authHeader.split(' ')[1];
    if (token !== this.scrapeToken) {
       throw new UnauthorizedException('Metrics access denied (Invalid Token)');
    }

    return true;
  }
}
