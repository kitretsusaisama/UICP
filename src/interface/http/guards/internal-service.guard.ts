import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';

@Injectable()
export class InternalServiceGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();

    const internalToken = process.env.INTERNAL_TOKEN;
    if (!internalToken && process.env.RELEASE_MODE === 'production') {
        throw new InternalServerErrorException('INTERNAL_TOKEN is strictly required in production');
    }
    const hasValidToken = req.headers['x-internal-token'] === internalToken;
    if (!hasValidToken) {
       throw new ForbiddenException('CORE_API_DEPRECATED: This API is internal only. External clients must migrate to /v1/users/me/*');
    }

    return true;
  }
}
