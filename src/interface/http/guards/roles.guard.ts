import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { TenantAwareRequest } from '../tenant/tenant-context';

export const SCOPES_KEY = 'scopes';
export const REQUIRED_SCOPES_KEY = 'required_scopes';

export interface ScopeOptions {
  requireAll?: boolean;
}

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (requiredRoles && requiredRoles.length > 0) {
      const req = context.switchToHttp().getRequest<TenantAwareRequest>();
      const roles = req.roles ?? req.user?.roles ?? [];
      const allowed = requiredRoles.some((role) => roles.includes(role));
      if (!allowed) {
        throw new ForbiddenException({
          error: { code: 'ROLE_FORBIDDEN', message: 'Required role is missing' },
        });
      }
    }

    const requiredScopes = this.reflector.getAllAndOverride<string[]>(REQUIRED_SCOPES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (requiredScopes && requiredScopes.length > 0) {
      const req = context.switchToHttp().getRequest<Record<string, unknown>>();
      const scopes = (req['scopes'] as string[] | undefined) ?? (req['apiKeyScopes'] as string[] | undefined) ?? [];
      const options = this.reflector.getAllAndOverride<ScopeOptions>(SCOPES_KEY, [
        context.getHandler(),
        context.getClass(),
      ]);

      const requireAll = options?.requireAll ?? false;
      const hasAccess = requireAll
        ? requiredScopes.every((scope) => scopes.includes(scope))
        : requiredScopes.some((scope) => scopes.includes(scope));

      if (!hasAccess) {
        throw new ForbiddenException({
          error: { code: 'SCOPE_FORBIDDEN', message: `Required scope(s) not granted: ${requiredScopes.join(', ')}` },
        });
      }
    }

    return true;
  }
}

