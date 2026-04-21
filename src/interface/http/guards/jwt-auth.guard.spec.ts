import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { TokenService } from '../../../application/services/token.service';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { AccessTokenPayload } from '../../../application/services/token.service';

// ── Helpers ──────────────────────────────────────────────────────────────────

function makePayload(overrides: Partial<AccessTokenPayload> = {}): AccessTokenPayload {
  return {
    iss: 'uicp',
    aud: 'uicp-api',
    sub: 'user-id-123',
    iat: Math.floor(Date.now() / 1000) - 60,
    exp: Math.floor(Date.now() / 1000) + 840,
    jti: 'jti-abc-123',
    tid: 'tenant-id-456',
    mid: 'membership-id-123',
    aid: 'actor-id-123',
    sid: 'session-id-789',
    pv: 'policy-version-1',
    mv: 'manifest-version-1',
    type: 'access',
    roles: ['user'],
    perms: ['read:profile'],
    capabilities: [],
    acr: 'aal1',
    mfa: false,
    amr: ['pwd'],
    ...overrides,
  };
}

function makeContext(authHeader?: string): { ctx: ExecutionContext; req: Record<string, unknown> } {
  const req: Record<string, unknown> = {
    headers: authHeader ? { authorization: authHeader } : {},
  };
  const ctx = {
    switchToHttp: () => ({ getRequest: () => req }),
  } as unknown as ExecutionContext;
  return { ctx, req };
}

function makeGuard(
  parseResult: (() => AccessTokenPayload) | Error,
  blocklisted = false,
): JwtAuthGuard {
  const tokenService = {
    parseAccessToken: jest.fn(() => {
      if (parseResult instanceof Error) throw parseResult;
      return parseResult();
    }),
  } as unknown as TokenService;

  const cache: ICachePort = {
    sismember: jest.fn().mockResolvedValue(blocklisted),
  } as unknown as ICachePort;

  return new JwtAuthGuard(tokenService, cache);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('JwtAuthGuard', () => {
  describe('missing or malformed Authorization header', () => {
    it('throws 401 when Authorization header is absent', async () => {
      const guard = makeGuard(() => makePayload());
      const { ctx } = makeContext(undefined);
      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
    });

    it('throws 401 when Authorization header does not start with Bearer', async () => {
      const guard = makeGuard(() => makePayload());
      const { ctx } = makeContext('Basic dXNlcjpwYXNz');
      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
    });

    it('includes MISSING_TOKEN error code', async () => {
      const guard = makeGuard(() => makePayload());
      const { ctx } = makeContext(undefined);
      try {
        await guard.canActivate(ctx);
        fail('expected to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(UnauthorizedException);
        const body = (err as UnauthorizedException).getResponse() as Record<string, unknown>;
        expect((body['error'] as Record<string, unknown>)['code']).toBe('MISSING_TOKEN');
      }
    });
  });

  describe('invalid token — signature / expiry', () => {
    it('throws 401 when token has an invalid signature', async () => {
      const guard = makeGuard(new Error('invalid signature'));
      const { ctx } = makeContext('Bearer bad.token.here');
      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
    });

    it('throws 401 when token is expired', async () => {
      const guard = makeGuard(new Error('jwt expired'));
      const { ctx } = makeContext('Bearer expired.token.here');
      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
    });

    it('includes INVALID_TOKEN error code on parse failure', async () => {
      const guard = makeGuard(new Error('jwt expired'));
      const { ctx } = makeContext('Bearer expired.token.here');
      try {
        await guard.canActivate(ctx);
        fail('expected to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(UnauthorizedException);
        const body = (err as UnauthorizedException).getResponse() as Record<string, unknown>;
        expect((body['error'] as Record<string, unknown>)['code']).toBe('INVALID_TOKEN');
      }
    });
  });

  describe('blocklisted jti', () => {
    it('throws 401 when jti is in the Redis blocklist', async () => {
      const guard = makeGuard(() => makePayload({ jti: 'revoked-jti' }), true);
      const { ctx } = makeContext('Bearer valid.looking.token');
      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
    });

    it('includes TOKEN_REVOKED error code for blocklisted jti', async () => {
      const guard = makeGuard(() => makePayload({ jti: 'revoked-jti' }), true);
      const { ctx } = makeContext('Bearer valid.looking.token');
      try {
        await guard.canActivate(ctx);
        fail('expected to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(UnauthorizedException);
        const body = (err as UnauthorizedException).getResponse() as Record<string, unknown>;
        expect((body['error'] as Record<string, unknown>)['code']).toBe('TOKEN_REVOKED');
      }
    });

    it('checks the blocklist with the correct jti value', async () => {
      const jti = 'specific-jti-value';
      const tokenService = {
        parseAccessToken: jest.fn(() => makePayload({ jti })),
      } as unknown as TokenService;
      const cache: ICachePort = {
        sismember: jest.fn().mockResolvedValue(true),
      } as unknown as ICachePort;

      const guard = new JwtAuthGuard(tokenService, cache);
      const { ctx } = makeContext('Bearer some.token');

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      expect(cache.sismember).toHaveBeenCalledWith('jwt:blocklist', jti);
    });
  });

  describe('valid token', () => {
    it('returns true for a valid, non-blocklisted token', async () => {
      const guard = makeGuard(() => makePayload(), false);
      const { ctx } = makeContext('Bearer valid.token.here');
      await expect(guard.canActivate(ctx)).resolves.toBe(true);
    });

    it('populates request context fields from the token payload', async () => {
      const payload = makePayload({
        sub: 'user-abc',
        sid: 'session-xyz',
        tid: 'tenant-999',
        roles: ['admin'],
        perms: ['write:users'],
      });
      const guard = makeGuard(() => payload, false);
      const { ctx, req } = makeContext('Bearer valid.token.here');

      await guard.canActivate(ctx);

      expect(req['userId']).toBe('user-abc');
      expect(req['sessionId']).toBe('session-xyz');
      expect(req['jwtTid']).toBe('tenant-999');
      expect(req['roles']).toEqual(['admin']);
      expect(req['perms']).toEqual(['write:users']);
    });
  });
});
