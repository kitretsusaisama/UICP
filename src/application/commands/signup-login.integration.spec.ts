/**
 * Integration tests for signup and login flows.
 *
 * Tests the application-layer command handlers with real domain logic
 * and mocked infrastructure adapters (no real DB/Redis).
 *
 * Implements: Req 2.3, Req 3.5–3.7, Req 7.4
 */
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { ClsService } from 'nestjs-cls';
import { randomUUID } from 'crypto';
import * as jwt from 'jsonwebtoken';
import { generateKeyPairSync } from 'crypto';

import { SignupEmailHandler } from './signup-email/signup-email.handler';
import { SignupEmailCommand } from './signup-email/signup-email.command';
import { LoginHandler } from './login/login.handler';
import { LoginCommand } from './login/login.command';
import { RefreshTokenHandler } from './refresh-token/refresh-token.handler';
import { RefreshTokenCommand } from './refresh-token/refresh-token.command';

import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { CredentialService } from '../services/credential.service';
import { SessionService } from '../services/session.service';
import { TokenService } from '../services/token.service';
import { DistributedLockService } from '../services/distributed-lock.service';
import { OtpService } from '../services/otp.service';
import { IdempotencyService } from '../services/idempotency.service';
import { RuntimeIdentityService } from '../services/runtime-identity.service';

import { DomainException } from '../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../domain/exceptions/domain-error-codes';
import { User } from '../../domain/aggregates/user.aggregate';
import { UserId } from '../../domain/value-objects/user-id.vo';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { Email } from '../../domain/value-objects/email.vo';
import { Credential } from '../../domain/entities/credential.entity';
import { Identity, toEncryptedValue } from '../../domain/entities/identity.entity';
import { IdentityId } from '../../domain/value-objects/identity-id.vo';
import { ConflictException } from '@nestjs/common';
import { LockToken } from '../ports/driven/i-lock.port';
import { UicpLogger } from '../../shared/logger/pino-logger.service';

// ── RSA key pair for JWT signing in tests ─────────────────────────────────────
const { privateKey: TEST_PRIVATE_KEY, publicKey: TEST_PUBLIC_KEY } =
  generateKeyPairSync('rsa', { modulusLength: 2048 });

const TEST_PRIVATE_KEY_PEM = TEST_PRIVATE_KEY.export({ type: 'pkcs8', format: 'pem' }) as string;
const TEST_PUBLIC_KEY_PEM = TEST_PUBLIC_KEY.export({ type: 'spki', format: 'pem' }) as string;
const TEST_KID = 'test-kid-1';
const TEST_ISSUER = 'https://test.identity.example.com';
const TEST_AUDIENCE = 'https://test.api.example.com';
const TEST_TENANT_ID = randomUUID();

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeMockLockPort() {
  return {
    acquire: jest.fn().mockResolvedValue({
      key: 'test-lock',
      value: randomUUID(),
      acquiredAt: new Date(),
      ttlMs: 10000,
    } as LockToken),
    release: jest.fn().mockResolvedValue(undefined),
    extend: jest.fn().mockResolvedValue(undefined),
  };
}

function makeMockCachePort() {
  const store = new Map<string, string>();
  return {
    get: jest.fn().mockImplementation(async (key: string) => store.get(key) ?? null),
    set: jest.fn().mockImplementation(async (key: string, value: string) => { store.set(key, value); }),
    del: jest.fn().mockImplementation(async (key: string) => { store.delete(key); }),
    getdel: jest.fn().mockImplementation(async (key: string) => {
      const value = store.get(key) ?? null;
      if (value !== null) store.delete(key);
      return value;
    }),
    sismember: jest.fn().mockResolvedValue(false),
    sadd: jest.fn().mockResolvedValue(1),
    srem: jest.fn().mockResolvedValue(1),
    smembers: jest.fn().mockResolvedValue([]),
    incr: jest.fn().mockResolvedValue(1),
    expire: jest.fn().mockResolvedValue(true),
  };
}

function makeMockSessionStore() {
  return {
    create: jest.fn().mockResolvedValue(undefined),
    findById: jest.fn().mockResolvedValue(null),
    findByUserId: jest.fn().mockResolvedValue([]),
    invalidate: jest.fn().mockResolvedValue(undefined),
    invalidateAll: jest.fn().mockResolvedValue(undefined),
    extendTtl: jest.fn().mockResolvedValue(undefined),
    setStatus: jest.fn().mockResolvedValue(undefined),
  };
}

function makeMockOutboxRepo() {
  return {
    insertWithinTransaction: jest.fn().mockResolvedValue(undefined),
    claimPendingBatch: jest.fn().mockResolvedValue([]),
    markPublished: jest.fn().mockResolvedValue(undefined),
    markFailed: jest.fn().mockResolvedValue(undefined),
    moveToDlq: jest.fn().mockResolvedValue(undefined),
  };
}

function makeMockQueuePort() {
  return {
    enqueue: jest.fn().mockResolvedValue(undefined),
    enqueueRepeatable: jest.fn().mockResolvedValue(undefined),
  };
}

function makeMockMetricsPort() {
  return {
    increment: jest.fn(),
    gauge: jest.fn(),
    histogram: jest.fn(),
    observe: jest.fn(),
  };
}

function makeMockTracerPort() {
  const span = {
    setAttributes: jest.fn(),
    recordException: jest.fn(),
    end: jest.fn(),
  };
  return {
    startSpan: jest.fn().mockReturnValue(span),
    setAttributes: jest.fn(),
    recordException: jest.fn(),
    getCurrentTraceId: jest.fn().mockReturnValue(undefined),
    withSpan: jest.fn().mockImplementation(async (_name: string, fn: () => Promise<unknown>) => fn()),
  };
}

function makeMockClsService() {
  const store = new Map<string, unknown>();
  return {
    get: jest.fn().mockImplementation((key: string) => store.get(key)),
    set: jest.fn().mockImplementation((key: string, value: unknown) => { store.set(key, value); }),
    getId: jest.fn().mockReturnValue(randomUUID()),
    run: jest.fn().mockImplementation(async (fn: () => unknown) => fn()),
  };
}

function makeConfigService(overrides: Record<string, unknown> = {}) {
  const defaults: Record<string, unknown> = {
    BCRYPT_ROUNDS: 4, // low rounds for fast tests
    PASSWORD_PEPPER: 'test-pepper-secret',
    JWT_PRIVATE_KEY_ENC: TEST_PRIVATE_KEY_PEM,
    JWT_PUBLIC_KEY: TEST_PUBLIC_KEY_PEM,
    JWT_KID: TEST_KID,
    JWT_ISSUER: TEST_ISSUER,
    JWT_AUDIENCE: TEST_AUDIENCE,
    JWT_ACCESS_TOKEN_TTL_S: 900,
    JWT_REFRESH_TOKEN_TTL_S: 604800,
    SESSION_TTL_S: 86400,
    MAX_SESSIONS_PER_USER: 10,
    OTP_TTL_S: 300,
    ...overrides,
  };
  return {
    get: jest.fn().mockImplementation((key: string, defaultVal?: unknown) => defaults[key] ?? defaultVal),
    getOrThrow: jest.fn().mockImplementation((key: string) => {
      if (!(key in defaults)) throw new Error(`Config key not found: ${key}`);
      return defaults[key];
    }),
  };
}

/** Build a reconstituted User with a real bcrypt credential for the given password. */
async function buildActiveUser(
  credentialService: CredentialService,
  password: string,
  status: 'ACTIVE' | 'DELETED' | 'SUSPENDED' | 'PENDING' = 'ACTIVE',
  suspendUntil?: Date,
): Promise<User> {
  const userId = UserId.create();
  const tenantId = TenantId.from(TEST_TENANT_ID);
  const identityId = IdentityId.create();

  const identity = Identity.reconstitute({
    id: identityId,
    tenantId,
    userId,
    type: 'EMAIL',
    valueEnc: toEncryptedValue('enc-email'),
    valueHash: 'test-email-hash',
    verified: status === 'ACTIVE',
    createdAt: new Date(),
  });

  const credential = await credentialService.hash({ getValue: () => password } as any);

  return User.reconstitute({
    id: userId,
    tenantId,
    status,
    identities: [identity],
    credential,
    suspendUntil,
    version: 1,
    createdAt: new Date(),
    updatedAt: new Date(),
  });
}

/** Build a mock identity that points to a given userId. */
function buildMockIdentity(userId: UserId): Identity {
  const tenantId = TenantId.from(TEST_TENANT_ID);
  return Identity.reconstitute({
    id: IdentityId.create(),
    tenantId,
    userId,
    type: 'EMAIL',
    valueEnc: toEncryptedValue('enc-email'),
    valueHash: 'test-email-hash',
    verified: true,
    createdAt: new Date(),
  });
}

// ── Test module factory ───────────────────────────────────────────────────────

/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyMock = jest.Mock<any, any>;

interface MockUserRepo {
  findById: AnyMock;
  findByTenantId: AnyMock;
  save: AnyMock;
  update: AnyMock;
}

interface MockIdentityRepo {
  findByHash: AnyMock;
  findByUserId: AnyMock;
  findByProviderSub: AnyMock;
  save: AnyMock;
  verify: AnyMock;
}

interface MockTokenRepo {
  saveRefreshToken: AnyMock;
  findRefreshToken: AnyMock;
  revokeToken: AnyMock;
  revokeFamily: AnyMock;
  revokeAllFamiliesByUser: AnyMock;
  isBlocklisted: AnyMock;
  addToBlocklist: AnyMock;
  getActiveJtisByUser: AnyMock;
}

interface TestModuleHandles {
  module: TestingModule;
  signupHandler: SignupEmailHandler;
  loginHandler: LoginHandler;
  refreshHandler: RefreshTokenHandler;
  credentialService: CredentialService;
  mockUserRepo: MockUserRepo;
  mockIdentityRepo: MockIdentityRepo;
  mockTokenRepo: MockTokenRepo;
  mockOutboxRepo: Record<string, AnyMock>;
  mockEncryption: Record<string, AnyMock>;
  mockQueuePort: Record<string, AnyMock>;
  mockCachePort: Record<string, AnyMock>;
  mockSessionStore: Record<string, AnyMock>;
  mockRuntimeIdentityService: {
    ensureForLegacyUser: AnyMock;
    getContext: AnyMock;
    listMemberships: AnyMock;
    listActors: AnyMock;
    findActor: AnyMock;
  };
}

async function createTestModule(
  configOverrides: Record<string, unknown> = {},
): Promise<TestModuleHandles> {
  const mockUserRepo: MockUserRepo = {
    findById: jest.fn(),
    findByTenantId: jest.fn().mockResolvedValue([]),
    save: jest.fn().mockResolvedValue(undefined),
    update: jest.fn().mockResolvedValue(undefined),
  };

  const mockIdentityRepo: MockIdentityRepo = {
    findByHash: jest.fn().mockResolvedValue(null),
    findByUserId: jest.fn().mockResolvedValue([]),
    findByProviderSub: jest.fn().mockResolvedValue(null),
    save: jest.fn().mockResolvedValue(undefined),
    verify: jest.fn().mockResolvedValue(undefined),
  };

  const mockTokenRepo: MockTokenRepo = {
    saveRefreshToken: jest.fn().mockResolvedValue(undefined),
    findRefreshToken: jest.fn().mockResolvedValue(null),
    revokeToken: jest.fn().mockResolvedValue(undefined),
    revokeFamily: jest.fn().mockResolvedValue(undefined),
    revokeAllFamiliesByUser: jest.fn().mockResolvedValue(undefined),
    isBlocklisted: jest.fn().mockResolvedValue(false),
    addToBlocklist: jest.fn().mockResolvedValue(undefined),
    getActiveJtisByUser: jest.fn().mockResolvedValue([]),
  };

  const mockOutboxRepo = makeMockOutboxRepo();
  const mockQueuePort = makeMockQueuePort();
  const mockCachePort = makeMockCachePort();
  const mockSessionStore = makeMockSessionStore();
  const mockLockPort = makeMockLockPort();
  const mockMetricsPort = makeMockMetricsPort();
  const mockTracerPort = makeMockTracerPort();
  const mockClsService = makeMockClsService();
  const mockRuntimeIdentityService = {
    ensureForLegacyUser: jest.fn().mockImplementation(async (user: User) => ({
      principalId: user.getId().toString(),
      principalStatus: user.getStatus(),
      tenantId: user.getTenantId().toString(),
      membershipId: randomUUID(),
      membershipStatus: 'ACTIVE',
      tenantType: 'workspace',
      isolationTier: 'shared',
      runtimeStatus: 'ACTIVE',
      actorId: randomUUID(),
      actorType: 'member',
      actorStatus: 'ACTIVE',
      actorDisplayName: 'Member',
      authMethodsSummary: [],
    })),
    getContext: jest.fn().mockResolvedValue(null),
    listMemberships: jest.fn().mockResolvedValue([]),
    listActors: jest.fn().mockResolvedValue([]),
    findActor: jest.fn().mockResolvedValue(null),
  };
  const mockLogger = {
    log: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  };
  const configService = makeConfigService(configOverrides);

  const mockEncryption = {
    encrypt: jest.fn().mockResolvedValue(toEncryptedValue('encrypted-value')),
    decrypt: jest.fn().mockResolvedValue('decrypted-value'),
    hmac: jest.fn().mockResolvedValue('test-email-hash'),
    encryptLarge: jest.fn().mockResolvedValue(toEncryptedValue('encrypted-large')),
    decryptLarge: jest.fn().mockResolvedValue('decrypted-large'),
  };

  const module = await Test.createTestingModule({
    providers: [
      SignupEmailHandler,
      LoginHandler,
      RefreshTokenHandler,
      CredentialService,
      SessionService,
      TokenService,
      DistributedLockService,
      OtpService,
      IdempotencyService,
      { provide: RuntimeIdentityService, useValue: mockRuntimeIdentityService },
      { provide: ConfigService, useValue: configService },
      { provide: ClsService, useValue: mockClsService },
      { provide: UicpLogger, useValue: mockLogger },
      { provide: INJECTION_TOKENS.USER_REPOSITORY, useValue: mockUserRepo },
      { provide: INJECTION_TOKENS.IDENTITY_REPOSITORY, useValue: mockIdentityRepo },
      { provide: INJECTION_TOKENS.TOKEN_REPOSITORY, useValue: mockTokenRepo },
      { provide: INJECTION_TOKENS.OUTBOX_REPOSITORY, useValue: mockOutboxRepo },
      { provide: INJECTION_TOKENS.ENCRYPTION_PORT, useValue: mockEncryption },
      { provide: INJECTION_TOKENS.QUEUE_PORT, useValue: mockQueuePort },
      { provide: INJECTION_TOKENS.CACHE_PORT, useValue: mockCachePort },
      { provide: INJECTION_TOKENS.SESSION_STORE, useValue: mockSessionStore },
      { provide: INJECTION_TOKENS.LOCK_PORT, useValue: mockLockPort },
      { provide: INJECTION_TOKENS.METRICS_PORT, useValue: mockMetricsPort },
      { provide: INJECTION_TOKENS.TRACER_PORT, useValue: mockTracerPort },
    ],
  }).compile();

  return {
    module,
    signupHandler: module.get(SignupEmailHandler),
    loginHandler: module.get(LoginHandler),
    refreshHandler: module.get(RefreshTokenHandler),
    credentialService: module.get(CredentialService),
    mockUserRepo,
    mockIdentityRepo,
    mockTokenRepo,
    mockOutboxRepo,
    mockEncryption,
    mockQueuePort,
    mockCachePort,
    mockSessionStore,
    mockRuntimeIdentityService,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('SignupEmailHandler integration', () => {
  let handles: TestModuleHandles;

  beforeEach(async () => {
    handles = await createTestModule();
  });

  afterEach(async () => {
    await handles.module.close();
  });

  /**
   * Req 2.3: duplicate identity returns IDENTITY_ALREADY_EXISTS
   */
  it('should throw IDENTITY_ALREADY_EXISTS on duplicate signup', async () => {
    const { signupHandler, mockIdentityRepo } = handles;

    // Arrange: identity already exists for this email hash
    const existingIdentity = buildMockIdentity(UserId.create());
    mockIdentityRepo.findByHash.mockResolvedValue(existingIdentity);

    const cmd = new SignupEmailCommand(
      TEST_TENANT_ID,
      'alice@example.com',
      'P@ssw0rd!Secure1',
    );

    // Act & Assert
    await expect(signupHandler.handle(cmd)).rejects.toThrow(ConflictException);
    await expect(signupHandler.handle(cmd)).rejects.toMatchObject({
      message: 'IDENTITY_ALREADY_EXISTS',
    });
  });

  it('should successfully create a new user and return userId', async () => {
    const { signupHandler, mockIdentityRepo, mockUserRepo, mockQueuePort } = handles;

    // Arrange: no existing identity
    mockIdentityRepo.findByHash.mockResolvedValue(null);
    mockUserRepo.save.mockResolvedValue(undefined);

    const cmd = new SignupEmailCommand(
      TEST_TENANT_ID,
      'newuser@example.com',
      'P@ssw0rd!Secure1',
    );

    // Act
    const result = await signupHandler.handle(cmd);

    // Assert
    expect(result.userId).toBeDefined();
    expect(result.message).toBe('Verification OTP sent');
    expect(mockUserRepo.save).toHaveBeenCalledTimes(1);
    expect(mockQueuePort.enqueue).toHaveBeenCalledWith('otp-send', expect.objectContaining({
      recipient: 'newuser@example.com',
      channel: 'EMAIL',
      purpose: 'IDENTITY_VERIFICATION',
    }));
  });
});

describe('LoginHandler integration', () => {
  let handles: TestModuleHandles;

  beforeEach(async () => {
    handles = await createTestModule();
  });

  afterEach(async () => {
    await handles.module.close();
  });

  /**
   * Req 3.5: login with DELETED account returns ACCOUNT_DELETED
   */
  it('should throw ACCOUNT_DELETED when user status is DELETED', async () => {
    const { loginHandler, credentialService, mockIdentityRepo, mockUserRepo } = handles;

    // Arrange: build a DELETED user
    const deletedUser = await buildActiveUser(credentialService, 'P@ssw0rd!Secure1', 'DELETED');
    const identity = buildMockIdentity(deletedUser.getId());

    mockIdentityRepo.findByHash.mockResolvedValue(identity);
    mockUserRepo.findById.mockResolvedValue(deletedUser);

    const cmd = new LoginCommand(
      TEST_TENANT_ID,
      'deleted@example.com',
      'P@ssw0rd!Secure1',
      'ip-hash-abc',
      'Mozilla/5.0',
    );

    // Act & Assert
    await expect(loginHandler.handle(cmd)).rejects.toThrow(DomainException);
    await expect(loginHandler.handle(cmd)).rejects.toMatchObject({
      errorCode: DomainErrorCode.ACCOUNT_DELETED,
    });
  });

  /**
   * Req 3.6: login with SUSPENDED account returns ACCOUNT_SUSPENDED
   */
  it('should throw ACCOUNT_SUSPENDED when user is suspended with future suspendUntil', async () => {
    const { loginHandler, credentialService, mockIdentityRepo, mockUserRepo } = handles;

    // Arrange: build a SUSPENDED user with future suspension end
    const suspendUntil = new Date(Date.now() + 3600 * 1000); // 1 hour from now
    const suspendedUser = await buildActiveUser(
      credentialService,
      'P@ssw0rd!Secure1',
      'SUSPENDED',
      suspendUntil,
    );
    const identity = buildMockIdentity(suspendedUser.getId());

    mockIdentityRepo.findByHash.mockResolvedValue(identity);
    mockUserRepo.findById.mockResolvedValue(suspendedUser);

    const cmd = new LoginCommand(
      TEST_TENANT_ID,
      'suspended@example.com',
      'P@ssw0rd!Secure1',
      'ip-hash-abc',
      'Mozilla/5.0',
    );

    // Act & Assert
    await expect(loginHandler.handle(cmd)).rejects.toThrow(DomainException);
    await expect(loginHandler.handle(cmd)).rejects.toMatchObject({
      errorCode: DomainErrorCode.ACCOUNT_SUSPENDED,
    });
  });

  /**
   * Req 3.6: indefinitely suspended account also returns ACCOUNT_SUSPENDED
   */
  it('should throw ACCOUNT_SUSPENDED when user is suspended indefinitely', async () => {
    const { loginHandler, credentialService, mockIdentityRepo, mockUserRepo } = handles;

    // Arrange: SUSPENDED with no suspendUntil (indefinite)
    const suspendedUser = await buildActiveUser(
      credentialService,
      'P@ssw0rd!Secure1',
      'SUSPENDED',
      undefined, // indefinite
    );
    const identity = buildMockIdentity(suspendedUser.getId());

    mockIdentityRepo.findByHash.mockResolvedValue(identity);
    mockUserRepo.findById.mockResolvedValue(suspendedUser);

    const cmd = new LoginCommand(
      TEST_TENANT_ID,
      'suspended@example.com',
      'P@ssw0rd!Secure1',
      'ip-hash-abc',
      'Mozilla/5.0',
    );

    await expect(loginHandler.handle(cmd)).rejects.toMatchObject({
      errorCode: DomainErrorCode.ACCOUNT_SUSPENDED,
    });
  });

  /**
   * Req 3.7: login with PENDING account returns ACCOUNT_NOT_ACTIVATED
   */
  it('should throw ACCOUNT_NOT_ACTIVATED when user status is PENDING', async () => {
    const { loginHandler, credentialService, mockIdentityRepo, mockUserRepo } = handles;

    // Arrange: build a PENDING user (email not yet verified)
    const pendingUser = await buildActiveUser(credentialService, 'P@ssw0rd!Secure1', 'PENDING');
    const identity = buildMockIdentity(pendingUser.getId());

    mockIdentityRepo.findByHash.mockResolvedValue(identity);
    mockUserRepo.findById.mockResolvedValue(pendingUser);

    const cmd = new LoginCommand(
      TEST_TENANT_ID,
      'pending@example.com',
      'P@ssw0rd!Secure1',
      'ip-hash-abc',
      'Mozilla/5.0',
    );

    // Act & Assert
    await expect(loginHandler.handle(cmd)).rejects.toThrow(DomainException);
    await expect(loginHandler.handle(cmd)).rejects.toMatchObject({
      errorCode: DomainErrorCode.ACCOUNT_NOT_ACTIVATED,
    });
  });

  it('should throw INVALID_CREDENTIALS when identity is not found', async () => {
    const { loginHandler, mockIdentityRepo } = handles;

    // Arrange: no identity found
    mockIdentityRepo.findByHash.mockResolvedValue(null);

    const cmd = new LoginCommand(
      TEST_TENANT_ID,
      'unknown@example.com',
      'P@ssw0rd!Secure1',
      'ip-hash-abc',
      'Mozilla/5.0',
    );

    await expect(loginHandler.handle(cmd)).rejects.toMatchObject({
      errorCode: DomainErrorCode.INVALID_CREDENTIALS,
    });
  });

  it('should throw INVALID_CREDENTIALS when password is wrong', async () => {
    const { loginHandler, credentialService, mockIdentityRepo, mockUserRepo } = handles;

    const activeUser = await buildActiveUser(credentialService, 'CorrectP@ss1', 'ACTIVE');
    const identity = buildMockIdentity(activeUser.getId());

    mockIdentityRepo.findByHash.mockResolvedValue(identity);
    mockUserRepo.findById.mockResolvedValue(activeUser);

    const cmd = new LoginCommand(
      TEST_TENANT_ID,
      'user@example.com',
      'WrongP@ss1',
      'ip-hash-abc',
      'Mozilla/5.0',
    );

    await expect(loginHandler.handle(cmd)).rejects.toMatchObject({
      errorCode: DomainErrorCode.INVALID_CREDENTIALS,
    });
  });

  it('should return tokens on successful login', async () => {
    const { loginHandler, credentialService, mockIdentityRepo, mockUserRepo, mockTokenRepo } = handles;

    const password = 'P@ssw0rd!Secure1';
    const activeUser = await buildActiveUser(credentialService, password, 'ACTIVE');
    const identity = buildMockIdentity(activeUser.getId());

    mockIdentityRepo.findByHash.mockResolvedValue(identity);
    mockUserRepo.findById.mockResolvedValue(activeUser);
    mockTokenRepo.saveRefreshToken.mockResolvedValue(undefined);

    const cmd = new LoginCommand(
      TEST_TENANT_ID,
      'user@example.com',
      password,
      'ip-hash-abc',
      'Mozilla/5.0 Chrome/120',
    );

    const result = await loginHandler.handle(cmd);

    expect(result.accessToken).toBeDefined();
    expect(result.refreshToken).toBeDefined();
    expect(result.sessionId).toBeDefined();
    expect(result.expiresIn).toBe(900);
  });
});

describe('RefreshTokenHandler integration — token reuse detection', () => {
  let handles: TestModuleHandles;

  beforeEach(async () => {
    handles = await createTestModule();
  });

  afterEach(async () => {
    await handles.module.close();
  });

  /**
   * Req 7.4: token reuse returns REFRESH_TOKEN_REUSE and revokes all family tokens
   */
  it('should throw REFRESH_TOKEN_REUSE and revoke family when a rotated token is reused', async () => {
    const {
      refreshHandler,
      credentialService,
      mockTokenRepo,
      mockUserRepo,
      mockSessionStore,
    } = handles;

    // Arrange: build an active user
    const activeUser = await buildActiveUser(credentialService, 'P@ssw0rd!Secure1', 'ACTIVE');

    // Build a refresh token that is already revoked (simulating reuse)
    const familyId = randomUUID();
    const oldJti = randomUUID();

    // Mint a real refresh token JWT so parseRefreshToken succeeds
    const tokenService: TokenService = handles.module.get(TokenService);
    const { token: refreshToken } = tokenService.mintRefreshToken(
      activeUser.getId(),
      TenantId.from(TEST_TENANT_ID),
      familyId,
    );

    // Parse the token to get the actual jti
    const payload = tokenService.parseRefreshToken(refreshToken);
    const jti = payload.jti;

    // Mock: token is NOT blocklisted
    mockTokenRepo.isBlocklisted.mockResolvedValue(false);

    // Mock: token record exists but is already revoked (reuse scenario)
    mockTokenRepo.findRefreshToken.mockResolvedValue({
      jti,
      familyId,
      userId: activeUser.getId().toString(),
      tenantId: TEST_TENANT_ID,
      revoked: true, // <-- already rotated/revoked
      expiresAt: new Date(Date.now() + 604800 * 1000),
      createdAt: new Date(),
    });

    mockUserRepo.findById.mockResolvedValue(activeUser);
    mockSessionStore.findById = jest.fn().mockResolvedValue(null);

    const cmd = new RefreshTokenCommand(TEST_TENANT_ID, refreshToken);

    // Act & Assert
    await expect(refreshHandler.handle(cmd)).rejects.toThrow(DomainException);
    await expect(refreshHandler.handle(cmd)).rejects.toMatchObject({
      errorCode: DomainErrorCode.REFRESH_TOKEN_REUSE,
    });

    // Verify family revocation was called
    expect(mockTokenRepo.revokeFamily).toHaveBeenCalledWith(
      familyId,
      expect.objectContaining({ toString: expect.any(Function) }),
    );
  });

  it('should throw TOKEN_REVOKED when token is blocklisted', async () => {
    const { refreshHandler, credentialService, mockTokenRepo } = handles;

    const activeUser = await buildActiveUser(credentialService, 'P@ssw0rd!Secure1', 'ACTIVE');
    const familyId = randomUUID();

    const tokenService: TokenService = handles.module.get(TokenService);
    const { token: refreshToken } = tokenService.mintRefreshToken(
      activeUser.getId(),
      TenantId.from(TEST_TENANT_ID),
      familyId,
    );

    // Mock: token IS blocklisted
    mockTokenRepo.isBlocklisted.mockResolvedValue(true);

    const cmd = new RefreshTokenCommand(TEST_TENANT_ID, refreshToken);

    await expect(refreshHandler.handle(cmd)).rejects.toMatchObject({
      errorCode: DomainErrorCode.TOKEN_REVOKED,
    });
  });

  it('should successfully rotate a valid refresh token', async () => {
    const { refreshHandler, credentialService, mockTokenRepo, mockUserRepo } = handles;

    const activeUser = await buildActiveUser(credentialService, 'P@ssw0rd!Secure1', 'ACTIVE');
    const familyId = randomUUID();

    const tokenService: TokenService = handles.module.get(TokenService);
    const { token: refreshToken, jti } = tokenService.mintRefreshToken(
      activeUser.getId(),
      TenantId.from(TEST_TENANT_ID),
      familyId,
    );

    // Mock: not blocklisted, token record exists and is NOT revoked
    mockTokenRepo.isBlocklisted.mockResolvedValue(false);
    mockTokenRepo.findRefreshToken.mockResolvedValue({
      jti,
      familyId,
      userId: activeUser.getId().toString(),
      tenantId: TEST_TENANT_ID,
      revoked: false,
      expiresAt: new Date(Date.now() + 604800 * 1000),
      createdAt: new Date(),
    });
    mockUserRepo.findById.mockResolvedValue(activeUser);

    const cmd = new RefreshTokenCommand(TEST_TENANT_ID, refreshToken);
    const result = await refreshHandler.handle(cmd);

    expect(result.accessToken).toBeDefined();
    expect(result.refreshToken).toBeDefined();
    expect(result.expiresIn).toBe(900);
    expect(mockTokenRepo.revokeToken).toHaveBeenCalledWith(
      jti,
      expect.objectContaining({ toString: expect.any(Function) }),
    );
    expect(mockTokenRepo.saveRefreshToken).toHaveBeenCalledTimes(1);
  });
});
