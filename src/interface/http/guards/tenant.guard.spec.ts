import { ExecutionContext, ForbiddenException, UnprocessableEntityException } from '@nestjs/common';
import { TenantGuard } from './tenant.guard';

const VALID_UUID = 'a1b2c3d4-e5f6-4789-abcd-ef0123456789';
const OTHER_UUID = 'b2c3d4e5-f6a7-4890-bcde-f01234567890';

function makeContext(headers: Record<string, string>, extra: Record<string, unknown> = {}): ExecutionContext {
  const req: Record<string, unknown> = { headers, ...extra };
  return {
    switchToHttp: () => ({ getRequest: () => req }),
  } as unknown as ExecutionContext;
}

describe('TenantGuard', () => {
  let guard: TenantGuard;

  beforeEach(() => {
    guard = new TenantGuard();
  });

  describe('missing or invalid X-Tenant-ID header', () => {
    it('throws 422 when X-Tenant-ID header is absent', () => {
      const ctx = makeContext({});
      expect(() => guard.canActivate(ctx)).toThrow(UnprocessableEntityException);
    });

    it('throws 422 when X-Tenant-ID is an empty string', () => {
      const ctx = makeContext({ 'x-tenant-id': '' });
      expect(() => guard.canActivate(ctx)).toThrow(UnprocessableEntityException);
    });

    it('throws 422 when X-Tenant-ID is not a valid UUID v4', () => {
      const ctx = makeContext({ 'x-tenant-id': 'not-a-uuid' });
      expect(() => guard.canActivate(ctx)).toThrow(UnprocessableEntityException);
    });

    it('includes INVALID_TENANT_ID error code in the 422 response', () => {
      const ctx = makeContext({ 'x-tenant-id': 'bad-value' });
      try {
        guard.canActivate(ctx);
        fail('expected to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(UnprocessableEntityException);
        const body = (err as UnprocessableEntityException).getResponse() as Record<string, unknown>;
        expect((body['error'] as Record<string, unknown>)['code']).toBe('INVALID_TENANT_ID');
      }
    });
  });

  describe('JWT tid vs header mismatch', () => {
    it('throws 403 when JWT tid=A and X-Tenant-ID=B', () => {
      // Simulates JwtAuthGuard having already set jwtTid on the request
      const ctx = makeContext({ 'x-tenant-id': OTHER_UUID }, { jwtTid: VALID_UUID });
      expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
    });

    it('includes TENANT_MISMATCH error code in the 403 response', () => {
      const ctx = makeContext({ 'x-tenant-id': OTHER_UUID }, { jwtTid: VALID_UUID });
      try {
        guard.canActivate(ctx);
        fail('expected to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(ForbiddenException);
        const body = (err as ForbiddenException).getResponse() as Record<string, unknown>;
        expect((body['error'] as Record<string, unknown>)['code']).toBe('TENANT_MISMATCH');
      }
    });
  });

  describe('valid scenarios', () => {
    it('returns true and sets req.tenantId when header is valid and no JWT is present', () => {
      const req: Record<string, unknown> = { headers: { 'x-tenant-id': VALID_UUID } };
      const ctx = {
        switchToHttp: () => ({ getRequest: () => req }),
      } as unknown as ExecutionContext;

      const result = guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(req['tenantId']).toBe(VALID_UUID);
    });

    it('returns true when JWT tid matches X-Tenant-ID header', () => {
      const ctx = makeContext({ 'x-tenant-id': VALID_UUID }, { jwtTid: VALID_UUID });
      expect(guard.canActivate(ctx)).toBe(true);
    });

    it('accepts array header value and uses the first element', () => {
      const req: Record<string, unknown> = {
        headers: { 'x-tenant-id': [VALID_UUID, OTHER_UUID] },
      };
      const ctx = {
        switchToHttp: () => ({ getRequest: () => req }),
      } as unknown as ExecutionContext;

      expect(guard.canActivate(ctx)).toBe(true);
      expect(req['tenantId']).toBe(VALID_UUID);
    });
  });
});
