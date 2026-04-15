import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnprocessableEntityException,
} from '@nestjs/common';

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * TenantGuard — validates the X-Tenant-ID header and enforces tenant claim
 * consistency with the JWT `tid` claim when a token is present.
 *
 * Implements: Req 1.6
 *
 * Behaviour:
 *  1. Extracts `X-Tenant-ID` header — rejects with 422 if missing or not a UUID v4.
 *  2. If a JWT has already been decoded (by JwtAuthGuard running first), verifies
 *     that the `tid` claim matches the header value — rejects with 403 on mismatch.
 *  3. Sets `req.tenantId` for downstream use.
 */
@Injectable()
export class TenantGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Record<string, unknown> & { headers: Record<string, string | string[] | undefined> }>();

    const rawTenantId = req.headers['x-tenant-id'];
    const tenantId = Array.isArray(rawTenantId) ? rawTenantId[0] : rawTenantId;

    if (!tenantId || !UUID_REGEX.test(tenantId)) {
      throw new UnprocessableEntityException({
        error: {
          code: 'INVALID_TENANT_ID',
          message: 'X-Tenant-ID header must be a valid UUID v4',
        },
      });
    }

    // If JWT was already verified, ensure tid claim matches the header
    const jwtTid = req['jwtTid'] as string | undefined;
    if (jwtTid !== undefined && jwtTid !== tenantId) {
      throw new ForbiddenException({
        error: {
          code: 'TENANT_MISMATCH',
          message: 'JWT tid claim does not match X-Tenant-ID header',
        },
      });
    }

    req['tenantId'] = tenantId;
    return true;
  }
}
