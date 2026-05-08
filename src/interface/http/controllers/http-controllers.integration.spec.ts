/**
 * Integration tests for HTTP controllers.
 *
 * Tests the full NestJS HTTP layer with mocked application-layer handlers
 * and infrastructure ports. Uses @nestjs/testing + supertest.
 *
 * Implements: Req 2.8, Req 3.10, Req 7.6, Req 9.10
 */
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ClsService } from 'nestjs-cls';
import * as request from 'supertest';
import { generateKeyPairSync, randomUUID } from 'crypto';

// Controllers
import { AuthController } from './auth.controller';
import { JwksController } from './jwks.controller';
import { IamController } from './iam.controller';

// Application layer
import { SignupEmailHandler } from '../../../application/commands/signup-email/signup-email.handler';
import { SignupPhoneHandler } from '../../../application/commands/signup-phone/signup-phone.handler';
import { LoginHandler } from '../../../application/commands/login/login.handler';
import { RefreshTokenHandler } from '../../../application/commands/refresh-token/refresh-token.handler';
import { LogoutHandler } from '../../../application/commands/logout/logout.handler';
import { LogoutAllHandler } from '../../../application/commands/logout-all/logout-all.handler';
import { VerifyOtpHandler } from '../../../application/commands/verify-otp/verify-otp.handler';
import { ChangePasswordHandler } from '../../../application/commands/change-password/change-password.handler';
import { PasswordResetRequestHandler } from '../../../application/commands/password-reset-request/password-reset-request.handler';
import { PasswordResetConfirmHandler } from '../../../application/commands/password-reset-confirm/password-reset-confirm.handler';
import { OAuthCallbackHandler } from '../../../application/commands/oauth-callback/oauth-callback.handler';
import { GetJwksHandler } from '../../../application/queries/get-jwks/get-jwks.handler';
import { OtpService } from '../../../application/services/otp.service';
import { TokenService } from '../../../application/services/token.service';
import { AbacPolicyEngine } from '../../../application/services/abac/abac-policy-engine';
import { RuntimeIdentityService } from '../../../application/services/runtime-identity.service';
import { SessionService } from '../../../application/services/session.service';

// Guards, interceptors, filters, middleware
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { IdempotencyInterceptor } from '../interceptors/idempotency.interceptor';
import { GlobalExceptionFilter } from '../filters/global-exception.filter';
import { RateLimiterMiddleware } from '../middleware/rate-limiter.middleware';
import { Request, Response, NextFunction } from 'express';
import { UicpLogger } from '../../../shared/logger/pino-logger.service';

// Ports & tokens
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';

// ── RSA key pair for JWT signing ──────────────────────────────────────────────

const { privateKey: TEST_PRIVATE_KEY, publicKey: TEST_PUBLIC_KEY } =
  generateKeyPairSync('rsa', { modulusLength: 2048 });

const TEST_PRIVATE_KEY_PEM = TEST_PRIVATE_KEY.export({ type: 'pkcs8', format: 'pem' }) as string;
const TEST_PUBLIC_KEY_PEM = TEST_PUBLIC_KEY.export({ type: 'spki', format: 'pem' }) as string;
const TEST_KID = 'test-kid-integration';
const TEST_ISSUER = 'https://test.uicp.example.com';
const TEST_AUDIENCE = 'https://test.api.example.com';
const TEST_TENANT_ID = randomUUID();

// ── Mock factories ────────────────────────────────────────────────────────────

function makeMockCachePort() {
  const store = new Map<string, string>();
  return {
    get: jest.fn().mockImplementation(async (key: string) => store.get(key) ?? null),
    set: jest.fn().mockImplementation(async (key: string, value: string) => {
      store.set(key, value);
    }),
    del: jest.fn().mockImplementation(async (key: string) => {
      store.delete(key);
    }),
    getdel: jest.fn().mockImplementation(async (key: string) => {
      const value = store.get(key) ?? null;
      if (value !== null) {
        store.delete(key);
      }
      return value;
    }),
    sismember: jest.fn().mockResolvedValue(false),
    sadd: jest.fn().mockResolvedValue(1),
    srem: jest.fn().mockResolvedValue(1),
    smembers: jest.fn().mockResolvedValue([]),
    incr: jest.fn().mockImplementation(async (key: string) => {
      const current = parseInt(store.get(key) ?? '0', 10);
      const next = current + 1;
      store.set(key, String(next));
      return next;
    }),
    expire: jest.fn().mockResolvedValue(true),
    _store: store,
  };
}

function makeConfigService() {
  const cfg: Record<string, unknown> = {
    JWT_PRIVATE_KEY_ENC: TEST_PRIVATE_KEY_PEM,
    JWT_PUBLIC_KEY: TEST_PUBLIC_KEY_PEM,
    JWT_KID: TEST_KID,
    JWT_ISSUER: TEST_ISSUER,
    JWT_AUDIENCE: TEST_AUDIENCE,
    JWT_ACCESS_TOKEN_TTL_S: 900,
    JWT_REFRESH_TOKEN_TTL_S: 604800,
    BCRYPT_ROUNDS: 4,
    PASSWORD_PEPPER: 'test-pepper',
    SESSION_TTL_S: 86400,
    MAX_SESSIONS_PER_USER: 10,
    OTP_TTL_S: 300,
    OIDC_ISSUER: TEST_ISSUER,
  };
  return {
    get: jest.fn().mockImplementation((key: string, def?: unknown) => cfg[key] ?? def),
    getOrThrow: jest.fn().mockImplementation((key: string) => {
      if (!(key in cfg)) throw new Error(`Config key not found: ${key}`);
      return cfg[key];
    }),
  };
}

function makeMockAbacPolicyRepo() {
  return {
    findByTenantId: jest.fn().mockResolvedValue([]),
    findById: jest.fn().mockResolvedValue(null),
    save: jest.fn().mockResolvedValue(undefined),
    delete: jest.fn().mockResolvedValue(undefined),
  };
}

// ── Test NestJS module ────────────────────────────────────────────────────────

async function createApp(
  mockCachePort: ReturnType<typeof makeMockCachePort>,
  signupHandlerMock?: Partial<SignupEmailHandler>,
): Promise<INestApplication> {
  const configService = makeConfigService();
  const mockAbacPolicyRepo = makeMockAbacPolicyRepo();

  const mockTokenRepo = {
    saveRefreshToken: jest.fn().mockResolvedValue(undefined),
    findRefreshToken: jest.fn().mockResolvedValue(null),
    revokeToken: jest.fn().mockResolvedValue(undefined),
    revokeFamily: jest.fn().mockResolvedValue(undefined),
    revokeAllFamiliesByUser: jest.fn().mockResolvedValue(undefined),
    isBlocklisted: jest.fn().mockResolvedValue(false),
    addToBlocklist: jest.fn().mockResolvedValue(undefined),
    getActiveJtisByUser: jest.fn().mockResolvedValue([]),
  };

  const mockQueuePort = {
    enqueue: jest.fn().mockResolvedValue(undefined),
    enqueueRepeatable: jest.fn().mockResolvedValue(undefined),
  };

  const mockClsService = {
    get: jest.fn().mockReturnValue(undefined),
    set: jest.fn(),
    getId: jest.fn().mockReturnValue(randomUUID()),
    run: jest.fn().mockImplementation(async (fn: () => unknown) => fn()),
  };

  const mockMetricsPort = {
    increment: jest.fn(),
    gauge: jest.fn(),
    histogram: jest.fn(),
    observe: jest.fn(),
  };

  const mockLogger = {
    log: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  };
  const mockTokenService = {
    parseAccessToken: jest.fn().mockReturnValue({
      sub: randomUUID(),
      tid: TEST_TENANT_ID,
      mid: randomUUID(),
      aid: randomUUID(),
      sid: randomUUID(),
      pv: 'policy-v1',
      mv: 'manifest-v1',
      capabilities: ['identity.session.read', 'tenant.actor.switch'],
      acr: 'aal1',
      amr: ['pwd'],
    }),
    getPublicKey: jest.fn().mockReturnValue(TEST_PUBLIC_KEY_PEM),
    getKid: jest.fn().mockReturnValue(TEST_KID),
    getDeprecatedPublicKeys: jest.fn().mockReturnValue([]),
  };
  const mockRuntimeIdentityService = {
    getContext: jest.fn().mockResolvedValue({
      principalId: randomUUID(),
      principalStatus: 'ACTIVE',
      tenantId: TEST_TENANT_ID,
      membershipId: randomUUID(),
      membershipStatus: 'ACTIVE',
      tenantType: 'workspace',
      isolationTier: 'shared',
      runtimeStatus: 'ACTIVE',
      actorId: randomUUID(),
      actorType: 'member',
      actorStatus: 'ACTIVE',
      actorDisplayName: 'Member',
      authMethodsSummary: [{ id: randomUUID(), type: 'EMAIL', verified: true }],
    }),
  };
  const mockSessionService = {
    findById: jest.fn().mockResolvedValue(null),
  };

  // Default signup handler — succeeds
  const defaultSignupHandler = {
    handle: jest.fn().mockResolvedValue({
      userId: randomUUID(),
      message: 'Verification OTP sent',
    }),
  };

  const moduleRef: TestingModule = await Test.createTestingModule({
    controllers: [AuthController, JwksController, IamController],
    providers: [
      GetJwksHandler,
      OtpService,

      // AbacPolicyEngine — provide a real instance with mocked repository
      // so IamController's @Optional() injection resolves correctly
      {
        provide: AbacPolicyEngine,
        useFactory: (repo: ReturnType<typeof makeMockAbacPolicyRepo>) =>
          new AbacPolicyEngine(repo as any, undefined),
        inject: [INJECTION_TOKENS.ABAC_POLICY_REPOSITORY],
      },

      // Mocked command handlers
      { provide: SignupEmailHandler, useValue: { ...defaultSignupHandler, ...signupHandlerMock } },
      { provide: SignupPhoneHandler, useValue: { handle: jest.fn().mockResolvedValue({ userId: randomUUID(), message: 'Verification OTP sent' }) } },
      { provide: LoginHandler, useValue: { handle: jest.fn().mockResolvedValue({ accessToken: 'tok', refreshToken: 'rtok', sessionId: randomUUID(), expiresIn: 900 }) } },
      { provide: RefreshTokenHandler, useValue: { handle: jest.fn() } },
      { provide: LogoutHandler, useValue: { handle: jest.fn().mockResolvedValue({ loggedOut: true }) } },
      { provide: LogoutAllHandler, useValue: { handle: jest.fn().mockResolvedValue({ loggedOut: true }) } },
      { provide: VerifyOtpHandler, useValue: { handle: jest.fn().mockResolvedValue({ verified: true }) } },
      { provide: ChangePasswordHandler, useValue: { handle: jest.fn().mockResolvedValue({ changed: true }) } },
      { provide: PasswordResetRequestHandler, useValue: { handle: jest.fn().mockResolvedValue({ message: 'If the identity exists, a reset OTP has been sent.' }) } },
      { provide: PasswordResetConfirmHandler, useValue: { handle: jest.fn().mockResolvedValue({ reset: true }) } },
      { provide: OAuthCallbackHandler, useValue: { handle: jest.fn() } },

      // Config & CLS
      { provide: ConfigService, useValue: configService },
      { provide: ClsService, useValue: mockClsService },
      { provide: UicpLogger, useValue: mockLogger },
      { provide: TokenService, useValue: mockTokenService },
      { provide: RuntimeIdentityService, useValue: mockRuntimeIdentityService },
      { provide: SessionService, useValue: mockSessionService },

      // Ports
      { provide: INJECTION_TOKENS.CACHE_PORT, useValue: mockCachePort },
      { provide: INJECTION_TOKENS.QUEUE_PORT, useValue: mockQueuePort },
      { provide: INJECTION_TOKENS.TOKEN_REPOSITORY, useValue: mockTokenRepo },
      { provide: INJECTION_TOKENS.ABAC_POLICY_REPOSITORY, useValue: mockAbacPolicyRepo },
      { provide: INJECTION_TOKENS.METRICS_PORT, useValue: mockMetricsPort },

      // Guards & interceptors as providers so NestJS DI resolves them
      JwtAuthGuard,
      IdempotencyInterceptor,
      RateLimiterMiddleware,
    ],
  }).compile();

  const app = moduleRef.createNestApplication();
  app.useGlobalFilters(new GlobalExceptionFilter(mockMetricsPort, mockClsService as any, mockLogger as any));

  // Apply rate limiter middleware globally — the middleware's matchRule handles
  // path-based filtering internally (mirrors production AppModule setup)
  const rateLimiter = moduleRef.get(RateLimiterMiddleware);
  app.use((req: Request, res: Response, next: NextFunction) =>
    rateLimiter.use(req, res, next),
  );

  // Patch IamController: @Optional() on a union type (AbacPolicyEngine | undefined)
  // causes NestJS DI to inject undefined even when the provider is registered,
  // because TypeScript emits 'Object' as the reflected type for union types.
  // We manually inject the real engine instance after module compilation.
  const iamController = moduleRef.get(IamController);
  const policyEngine = new AbacPolicyEngine(mockAbacPolicyRepo as any, undefined);
  (iamController as any).policyEngine = policyEngine;

  await app.init();
  return app;
}

// ── Test suites ───────────────────────────────────────────────────────────────

describe('POST /v1/auth/signup — idempotency (Req 2.8)', () => {
  let app: INestApplication;
  let mockCachePort: ReturnType<typeof makeMockCachePort>;

  beforeEach(async () => {
    mockCachePort = makeMockCachePort();
    app = await createApp(mockCachePort);
  });

  afterEach(async () => {
    await app.close();
  });

  it('second call with same X-Idempotency-Key returns cached response with x-idempotency-replayed: true', async () => {
    const idempotencyKey = randomUUID();
    const body = { email: 'idempotent@example.com', password: 'P@ssw0rd!Secure1' };

    // First call — cache miss, handler executes
    const first = await request(app.getHttpServer())
      .post('/v1/auth/signup')
      .set('x-tenant-id', TEST_TENANT_ID)
      .set('x-idempotency-key', idempotencyKey)
      .send(body)
      .expect(201);

    expect(first.headers['x-idempotency-replayed']).toBeUndefined();
    expect(first.body.data.principalId).toBeDefined();

    // Second call — cache hit, replayed
    const second = await request(app.getHttpServer())
      .post('/v1/auth/signup')
      .set('x-tenant-id', TEST_TENANT_ID)
      .set('x-idempotency-key', idempotencyKey)
      .send(body)
      .expect(201);

    expect(second.headers['x-idempotency-replayed']).toBe('true');
    expect(second.body.data.principalId).toBe(first.body.data.principalId);
  });

  it('different idempotency keys produce independent responses', async () => {
    const body = { email: 'user@example.com', password: 'P@ssw0rd!Secure1' };

    const first = await request(app.getHttpServer())
      .post('/v1/auth/signup')
      .set('x-tenant-id', TEST_TENANT_ID)
      .set('x-idempotency-key', randomUUID())
      .send(body)
      .expect(201);

    const second = await request(app.getHttpServer())
      .post('/v1/auth/signup')
      .set('x-tenant-id', TEST_TENANT_ID)
      .set('x-idempotency-key', randomUUID())
      .send(body)
      .expect(201);

    // Both succeed independently — no replay header
    expect(first.headers['x-idempotency-replayed']).toBeUndefined();
    expect(second.headers['x-idempotency-replayed']).toBeUndefined();
  });

  it('request without idempotency key always executes handler', async () => {
    const body = { email: 'nokey@example.com', password: 'P@ssw0rd!Secure1' };

    const res = await request(app.getHttpServer())
      .post('/v1/auth/signup')
      .set('x-tenant-id', TEST_TENANT_ID)
      .send(body)
      .expect(201);

    expect(res.headers['x-idempotency-replayed']).toBeUndefined();
  });
});

describe('POST /v1/auth/login — rate limiting (Req 3.10)', () => {
  let app: INestApplication;
  let mockCachePort: ReturnType<typeof makeMockCachePort>;

  beforeEach(async () => {
    mockCachePort = makeMockCachePort();
    app = await createApp(mockCachePort);
  });

  afterEach(async () => {
    await app.close();
  });

  it('21st request within the same window returns HTTP 429', async () => {
    const body = { identity: 'user@example.com', password: 'P@ssw0rd!Secure1' };

    // Send 20 requests — all should succeed (limit is 20/min/IP)
    for (let i = 0; i < 20; i++) {
      await request(app.getHttpServer())
        .post('/v1/auth/login')
        .set('x-tenant-id', TEST_TENANT_ID)
        .set('x-forwarded-for', '10.0.0.1')
        .send(body)
        .expect(200);
    }

    // 21st request — should be rate limited
    const res = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .set('x-tenant-id', TEST_TENANT_ID)
      .set('x-forwarded-for', '10.0.0.1')
      .send(body)
      .expect(429);

    expect(res.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    expect(res.headers['retry-after']).toBeDefined();
    expect(res.headers['x-ratelimit-limit']).toBe('20');
    expect(res.headers['x-ratelimit-remaining']).toBe('0');
  });

  it('requests from different IPs have independent rate limit buckets', async () => {
    const body = { identity: 'user@example.com', password: 'P@ssw0rd!Secure1' };

    // Exhaust limit for IP A
    for (let i = 0; i < 20; i++) {
      await request(app.getHttpServer())
        .post('/v1/auth/login')
        .set('x-tenant-id', TEST_TENANT_ID)
        .set('x-forwarded-for', '10.0.0.2')
        .send(body)
        .expect(200);
    }

    // IP A is now rate limited
    await request(app.getHttpServer())
      .post('/v1/auth/login')
      .set('x-tenant-id', TEST_TENANT_ID)
      .set('x-forwarded-for', '10.0.0.2')
      .send(body)
      .expect(429);

    // IP B still has its own fresh bucket
    await request(app.getHttpServer())
      .post('/v1/auth/login')
      .set('x-tenant-id', TEST_TENANT_ID)
      .set('x-forwarded-for', '10.0.0.3')
      .send(body)
      .expect(200);
  });

  it('rate limit response includes Retry-After and X-RateLimit-Reset headers', async () => {
    const body = { identity: 'user@example.com', password: 'P@ssw0rd!Secure1' };

    // Exhaust limit
    for (let i = 0; i < 20; i++) {
      await request(app.getHttpServer())
        .post('/v1/auth/login')
        .set('x-tenant-id', TEST_TENANT_ID)
        .set('x-forwarded-for', '10.0.0.4')
        .send(body);
    }

    const res = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .set('x-tenant-id', TEST_TENANT_ID)
      .set('x-forwarded-for', '10.0.0.4')
      .send(body)
      .expect(429);

    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    expect(Number(res.headers['x-ratelimit-reset'])).toBeGreaterThan(0);
    expect(res.body.error.retryAfter).toBeGreaterThan(0);
  });
});

describe('GET /.well-known/jwks.json — JWKS endpoint (Req 7.6)', () => {
  let app: INestApplication;
  let mockCachePort: ReturnType<typeof makeMockCachePort>;

  beforeEach(async () => {
    mockCachePort = makeMockCachePort();
    app = await createApp(mockCachePort);
  });

  afterEach(async () => {
    await app.close();
  });

  it('returns HTTP 200 with a valid JWK Set', async () => {
    const res = await request(app.getHttpServer())
      .get('/.well-known/jwks.json')
      .expect(200);

    expect(res.body).toHaveProperty('keys');
    expect(Array.isArray(res.body.keys)).toBe(true);
    expect(res.body.keys.length).toBeGreaterThanOrEqual(1);
  });

  it('each key in the set has required JWK fields (kty, use, alg, kid, n, e)', async () => {
    const res = await request(app.getHttpServer())
      .get('/.well-known/jwks.json')
      .expect(200);

    for (const key of res.body.keys) {
      expect(key).toHaveProperty('kty', 'RSA');
      expect(key).toHaveProperty('use', 'sig');
      expect(key).toHaveProperty('alg', 'RS256');
      expect(key).toHaveProperty('kid');
      expect(key).toHaveProperty('n');
      expect(key).toHaveProperty('e');
      // n and e must be non-empty base64url strings
      expect(typeof key.n).toBe('string');
      expect(key.n.length).toBeGreaterThan(0);
      expect(typeof key.e).toBe('string');
      expect(key.e.length).toBeGreaterThan(0);
    }
  });

  it('response includes Cache-Control: public, max-age=3600 header (Req 7.6)', async () => {
    const res = await request(app.getHttpServer())
      .get('/.well-known/jwks.json')
      .expect(200);

    expect(res.headers['cache-control']).toBe('public, max-age=3600');
  });

  it('active key kid matches the configured JWT_KID', async () => {
    const res = await request(app.getHttpServer())
      .get('/.well-known/jwks.json')
      .expect(200);

    const kids = res.body.keys.map((k: { kid: string }) => k.kid);
    expect(kids).toContain(TEST_KID);
  });
});

describe('POST /v1/iam/policies/evaluate — dry-run evaluation (Req 9.10)', () => {
  let app: INestApplication;
  let mockCachePort: ReturnType<typeof makeMockCachePort>;

  beforeEach(async () => {
    mockCachePort = makeMockCachePort();
    app = await createApp(mockCachePort);
  });

  afterEach(async () => {
    await app.close();
  });

  it('returns evaluation result with result, matchedNodes, and executionTimeMs fields', async () => {
    const body = {
      condition: 'subject.role == "admin"',
      context: {
        subject: { role: 'admin' },
        resource: {},
        action: 'read',
        env: {},
      },
    };

    const res = await request(app.getHttpServer())
      .post('/v1/iam/policies/evaluate')
      .set('x-tenant-id', TEST_TENANT_ID)
      .send(body)
      .expect(200);

    expect(res.body.data).toHaveProperty('result', true);
    expect(res.body.data).toHaveProperty('matchedNodes');
    expect(Array.isArray(res.body.data.matchedNodes)).toBe(true);
    expect(res.body.data).toHaveProperty('executionTimeMs');
    expect(typeof res.body.data.executionTimeMs).toBe('number');
  });

  it('evaluates a DENY condition correctly (result: false)', async () => {
    const body = {
      condition: 'subject.role == "admin"',
      context: {
        subject: { role: 'viewer' },
        resource: {},
        action: 'read',
        env: {},
      },
    };

    const res = await request(app.getHttpServer())
      .post('/v1/iam/policies/evaluate')
      .set('x-tenant-id', TEST_TENANT_ID)
      .send(body)
      .expect(200);

    expect(res.body.data.result).toBe(false);
  });

  it('evaluates complex AND condition correctly', async () => {
    const body = {
      condition: 'subject.role == "admin" AND subject.department == "engineering"',
      context: {
        subject: { role: 'admin', department: 'engineering' },
        resource: {},
        action: 'write',
        env: {},
      },
    };

    const res = await request(app.getHttpServer())
      .post('/v1/iam/policies/evaluate')
      .set('x-tenant-id', TEST_TENANT_ID)
      .send(body)
      .expect(200);

    expect(res.body.data.result).toBe(true);
  });

  it('evaluates IN operator correctly', async () => {
    const body = {
      condition: 'subject.role IN ["admin", "superuser"]',
      context: {
        subject: { role: 'admin' },
        resource: {},
        action: 'delete',
        env: {},
      },
    };

    const res = await request(app.getHttpServer())
      .post('/v1/iam/policies/evaluate')
      .set('x-tenant-id', TEST_TENANT_ID)
      .send(body)
      .expect(200);

    expect(res.body.data.result).toBe(true);
  });

  it('returns HTTP 400 with INVALID_DSL when condition is syntactically invalid', async () => {
    const body = {
      condition: 'subject.role ??? "admin"',
      context: { subject: {}, resource: {}, action: '', env: {} },
    };

    const res = await request(app.getHttpServer())
      .post('/v1/iam/policies/evaluate')
      .set('x-tenant-id', TEST_TENANT_ID)
      .send(body)
      .expect(400);

    expect(res.body.error.code).toBe('INVALID_DSL');
  });

  it('returns HTTP 400 when x-tenant-id header is missing', async () => {
    const body = {
      condition: 'subject.role == "admin"',
      context: { subject: {}, resource: {}, action: '', env: {} },
    };

    const res = await request(app.getHttpServer())
      .post('/v1/iam/policies/evaluate')
      .send(body)
      .expect(400);

    expect(res.body.error.code).toBe('MISSING_TENANT_ID');
  });

  it('returns HTTP 400 when request body is missing required fields', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/iam/policies/evaluate')
      .set('x-tenant-id', TEST_TENANT_ID)
      .send({ condition: 'subject.role == "admin"' }) // missing context
      .expect(400);

    expect(res.body.error).toBeDefined();
  });

  it('includes warnings when context attributes are missing', async () => {
    const body = {
      condition: 'subject.nonExistentAttr == "value"',
      context: {
        subject: {},
        resource: {},
        action: '',
        env: {},
      },
    };

    const res = await request(app.getHttpServer())
      .post('/v1/iam/policies/evaluate')
      .set('x-tenant-id', TEST_TENANT_ID)
      .send(body)
      .expect(200);

    // Result is false (attribute not found), warnings may be present
    expect(res.body.data.result).toBe(false);
    expect(Array.isArray(res.body.data.warnings)).toBe(true);
  });
});
