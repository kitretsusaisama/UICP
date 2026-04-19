import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';

@Injectable()
export class InternalServiceGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();

    const internalToken = process.env.INTERNAL_TOKEN || 'local-internal-secret-token';
    const hasValidToken = req.headers['x-internal-token'] === internalToken;
    const isServiceMesh = !!req.headers['x-service-id']; // Simplified check for mTLS/mesh injected headers

    if (!hasValidToken && !isServiceMesh) {
       throw new ForbiddenException('CORE_API_DEPRECATED: This API is internal only. External clients must migrate to /v1/users/me/*');
    }

    return true;
  }
}
