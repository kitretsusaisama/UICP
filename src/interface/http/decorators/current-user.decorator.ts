import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { CurrentUserContext, TenantAwareRequest } from '../tenant/tenant-context';

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): CurrentUserContext => {
    const req = ctx.switchToHttp().getRequest<TenantAwareRequest>();
    return {
      ...req.user,
      principalId: req.principalId ?? req.user?.principalId,
      userId: req.userId ?? req.user?.userId,
      membershipId: req.membershipId ?? req.user?.membershipId,
      actorId: req.actorId ?? req.user?.actorId,
      sessionId: req.sessionId ?? req.user?.sessionId,
      roles: req.roles ?? req.user?.roles ?? [],
      capabilities: req.capabilities ?? req.user?.capabilities ?? [],
      tenantId: req.tenantId ?? req.jwtTid ?? req.user?.tenantId,
    };
  },
);

