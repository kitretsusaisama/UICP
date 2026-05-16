import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  UnprocessableEntityException,
} from '@nestjs/common';
import type { Pool, RowDataPacket } from 'mysql2/promise';
import { bufferToUuid } from '../../../infrastructure/db/mysql/uuid-utils';
import {
  extractSubdomain,
  getHeaderValue,
  TenantAwareRequest,
  TenantContext,
  UUID_V4_REGEX,
} from '../tenant/tenant-context';

interface TenantRow extends RowDataPacket {
  id: Buffer;
  slug: string;
  plan: string;
  status: string;
}

/**
 * Resolves tenant context from subdomain, X-Tenant-Slug, compatibility
 * X-Tenant-ID, or an already-verified JWT `tid` claim.
 */
@Injectable()
export class TenantGuard implements CanActivate {
  private readonly slugCache = new Map<string, { expiresAt: number; context: TenantContext }>();

  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<TenantAwareRequest>();
    const tenantContext = await this.resolveTenant(req);

    if (!tenantContext.id) {
      throw new UnprocessableEntityException({
        error: {
          code: 'INVALID_TENANT_ID',
          message: 'Tenant could not be resolved from subdomain, X-Tenant-Slug, X-Tenant-ID, or JWT',
        },
      });
    }

    if (req.jwtTid !== undefined && req.jwtTid !== tenantContext.id) {
      throw new ForbiddenException({
        error: {
          code: 'TENANT_MISMATCH',
          message: 'JWT tid claim does not match resolved tenant',
        },
      });
    }

    req.tenantContext = tenantContext;
    req.tenantId = tenantContext.id;
    req.tenantSlug = tenantContext.slug;
    return true;
  }

  private async resolveTenant(req: TenantAwareRequest): Promise<TenantContext> {
    const hostSlug = extractSubdomain(req.hostname ?? getHeaderValue(req.headers, 'host'));
    if (hostSlug) {
      return this.resolveSlug(hostSlug, 'subdomain');
    }

    const headerSlug = getHeaderValue(req.headers, 'x-tenant-slug');
    if (headerSlug) {
      return this.resolveSlug(headerSlug, 'header-slug');
    }

    const headerId = getHeaderValue(req.headers, 'x-tenant-id');
    if (headerId) {
      if (!UUID_V4_REGEX.test(headerId)) {
        throw new UnprocessableEntityException({
          error: {
            code: 'INVALID_TENANT_ID',
            message: 'X-Tenant-ID header must be a valid UUID v4',
          },
        });
      }

      return { id: headerId, source: 'header-id' };
    }

    if (req.jwtTid) {
      return { id: req.jwtTid, source: 'jwt' };
    }

    return { source: 'jwt' };
  }

  private async resolveSlug(slug: string, source: 'subdomain' | 'header-slug'): Promise<TenantContext> {
    const cached = this.slugCache.get(slug);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.context;
    }

    const [rows] = await this.pool.query<TenantRow[]>(
      'SELECT id, slug, plan, status FROM tenants WHERE slug = ? LIMIT 1',
      [slug],
    );
    const row = rows[0];
    if (!row) {
      throw new UnprocessableEntityException({
        error: { code: 'TENANT_NOT_FOUND', message: 'Tenant slug was not found' },
      });
    }

    const context: TenantContext = {
      id: bufferToUuid(row.id),
      slug: row.slug,
      plan: row.plan,
      isActive: row.status === 'active',
      source,
    };
    this.slugCache.set(slug, { context, expiresAt: Date.now() + 60_000 });
    return context;
  }
}
