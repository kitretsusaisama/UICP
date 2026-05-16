import { BadRequestException } from '@nestjs/common';

/**
 * @deprecated Use tenant-resolver.ts instead
 * This file is kept for backward compatibility
 */
export * from './tenant-resolver';

// Re-export for internal use in deprecated functions
import { parseTenantId as resolveParseTenantId } from './tenant-resolver';

// Re-export types for backward compatibility
export interface TenantContext {
  id?: string;
  slug?: string;
  plan?: string;
  isActive?: boolean;
  source: 'subdomain' | 'header-id' | 'header-slug' | 'jwt';
}

export interface CurrentUserContext {
  principalId?: string;
  userId?: string;
  membershipId?: string;
  actorId?: string;
  sessionId?: string;
  roles?: string[];
  capabilities?: string[];
  tenantId?: string;
}

export interface TenantAwareRequest {
  headers: Record<string, string | string[] | undefined>;
  hostname?: string;
  tenantContext?: TenantContext;
  tenantId?: string;
  tenantSlug?: string;
  jwtTid?: string;
  user?: CurrentUserContext;
  principalId?: string;
  userId?: string;
  membershipId?: string;
  actorId?: string;
  sessionId?: string;
  roles?: string[];
  capabilities?: string[];
}

/**
 * @deprecated Use getTenantIdOrThrow from tenant-resolver.ts instead
 */
export function currentTenantId(req: TenantAwareRequest): string {
  const headers = req.headers as Record<string, string | string[] | undefined> | undefined;
  const headerValue = headers?.['x-tenant-id'];
  const raw = typeof headerValue === 'string' ? headerValue : Array.isArray(headerValue) ? headerValue[0] : undefined;

  // Check header first
  if (raw) {
    return resolveParseTenantId(raw);
  }

  // Fall back to tenant context
  if (req.tenantContext?.id) {
    return resolveParseTenantId(req.tenantContext.id);
  }

  // Fall back to tenantId property
  if (req.tenantId) {
    return resolveParseTenantId(req.tenantId);
  }

  // Fall back to jwtTid
  if (req.jwtTid) {
    return resolveParseTenantId(req.jwtTid);
  }

  throw new BadRequestException({
    error: { code: 'MISSING_TENANT_ID', message: 'Tenant ID could not be resolved from headers or context' },
  });
}

