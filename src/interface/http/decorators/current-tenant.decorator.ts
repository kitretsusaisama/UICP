import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { TenantAwareRequest, TenantContext } from '../tenant/tenant-context';

export const CurrentTenant = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): TenantContext | undefined => {
    const req = ctx.switchToHttp().getRequest<TenantAwareRequest>();
    return req.tenantContext;
  },
);

