import { Test, TestingModule } from '@nestjs/testing';
import { RuntimeIdentityService } from './runtime-identity.service';
import { IRuntimeIdentityRepository, RuntimeIdentityContext, RuntimeMembershipSummary, RuntimeActorSummary } from '../ports/driven/i-runtime-identity.repository';
import { INJECTION_TOKENS } from '../ports/injection-tokens';
import { User } from '../../domain/aggregates/user.aggregate';
import { UserId } from '../../domain/value-objects/user-id.vo';
import { TenantId } from '../../domain/value-objects/tenant-id.vo';
import { randomUUID } from 'crypto';

/**
 * Unit tests for RuntimeIdentityService.
 *
 * Covers:
 *   - ensureForLegacyUser
 *   - getContext
 *   - listMemberships
 *   - listActors
 *   - findActor
 */

const mockRuntimeIdentityRepository = (): IRuntimeIdentityRepository => ({
  ensurePrincipalGraph: jest.fn(),
  findContext: jest.fn(),
  listMemberships: jest.fn(),
  listActors: jest.fn(),
  findActor: jest.fn(),
  listAuthMethods: jest.fn(),
});

const makeMockUser = (overrides: Partial<User> = {}): User => {
  const userId = randomUUID();
  const tenantId = randomUUID();
  const mock = {
    getId: () => UserId.from(userId),
    getTenantId: () => TenantId.from(tenantId),
    getStatus: () => 'ACTIVE',
    getIdentities: () => [
      {
        id: { toString: () => randomUUID() },
        getType: () => 'EMAIL',
        getValueHash: () => 'hash123',
        getProviderSub: () => undefined,
        isVerified: () => true,
        getVerifiedAt: () => new Date(),
      },
    ],
    ...overrides,
  } as User;
  return mock;
};

const makeMockContext = (overrides: Partial<RuntimeIdentityContext> = {}): RuntimeIdentityContext => ({
  principalId: randomUUID(),
  principalStatus: 'ACTIVE',
  tenantId: randomUUID(),
  membershipId: randomUUID(),
  membershipStatus: 'ACTIVE',
  tenantType: 'ORGANIZATION',
  isolationTier: 'TENANT',
  runtimeStatus: 'ACTIVE',
  actorId: randomUUID(),
  actorType: 'USER',
  actorStatus: 'ACTIVE',
  actorDisplayName: 'Test Actor',
  authMethodsSummary: [],
  ...overrides,
});

describe('RuntimeIdentityService', () => {
  let service: RuntimeIdentityService;
  let mockRepo: IRuntimeIdentityRepository;

  beforeEach(async () => {
    mockRepo = mockRuntimeIdentityRepository();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RuntimeIdentityService,
        {
          provide: INJECTION_TOKENS.RUNTIME_IDENTITY_REPOSITORY,
          useValue: mockRepo,
        },
      ],
    }).compile();

    service = module.get<RuntimeIdentityService>(RuntimeIdentityService);
    jest.clearAllMocks();
  });

  describe('ensureForLegacyUser', () => {
    it('should call ensurePrincipalGraph with correct user data', async () => {
      const user = makeMockUser();
      const expectedContext = makeMockContext();

      (mockRepo.ensurePrincipalGraph as jest.Mock).mockResolvedValue(expectedContext);

      const result = await service.ensureForLegacyUser(user);

      expect(mockRepo.ensurePrincipalGraph).toHaveBeenCalledWith(
        expect.objectContaining({
          principalId: user.getId().toString(),
          tenantId: user.getTenantId().toString(),
          principalStatus: user.getStatus(),
        }),
      );
      expect(result).toEqual(expectedContext);
    });

    it('should pass preferredActorType when provided', async () => {
      const user = makeMockUser();
      const expectedContext = makeMockContext();

      (mockRepo.ensurePrincipalGraph as jest.Mock).mockResolvedValue(expectedContext);

      await service.ensureForLegacyUser(user, 'SERVICE_ACCOUNT');

      expect(mockRepo.ensurePrincipalGraph).toHaveBeenCalledWith(
        expect.objectContaining({
          preferredActorType: 'SERVICE_ACCOUNT',
        }),
      );
    });

    it('should transform user identities to auth methods format', async () => {
      const user = makeMockUser();
      const expectedContext = makeMockContext();

      (mockRepo.ensurePrincipalGraph as jest.Mock).mockResolvedValue(expectedContext);

      await service.ensureForLegacyUser(user);

      const call = (mockRepo.ensurePrincipalGraph as jest.Mock).mock.calls[0][0];
      expect(call.authMethods).toHaveLength(1);
      expect(call.authMethods[0]).toMatchObject({
        type: 'EMAIL',
        verified: true,
      });
    });

    it('should handle OAuth identities with provider info', async () => {
      const oauthUser = makeMockUser({
        getIdentities: () => [
          {
            id: { toString: () => randomUUID() },
            getType: () => 'OAUTH_GOOGLE',
            getValueHash: () => 'hash456',
            getProviderSub: () => 'oauth-subject-123',
            isVerified: () => true,
            getVerifiedAt: () => new Date(),
          },
        ],
      } as User);
      const expectedContext = makeMockContext();

      (mockRepo.ensurePrincipalGraph as jest.Mock).mockResolvedValue(expectedContext);

      await service.ensureForLegacyUser(oauthUser);

      const call = (mockRepo.ensurePrincipalGraph as jest.Mock).mock.calls[0][0];
      expect(call.authMethods[0].providerName).toBe('google');
      expect(call.authMethods[0].providerSubject).toBe('oauth-subject-123');
    });
  });

  describe('getContext', () => {
    it('should call findContext with correct parameters', async () => {
      const principalId = randomUUID();
      const tenantId = randomUUID();
      const actorId = randomUUID();
      const expectedContext = makeMockContext({ actorId });

      (mockRepo.findContext as jest.Mock).mockResolvedValue(expectedContext);

      const result = await service.getContext(principalId, tenantId, actorId);

      expect(mockRepo.findContext).toHaveBeenCalledWith(principalId, tenantId, actorId);
      expect(result).toEqual(expectedContext);
    });

    it('should return null when context not found', async () => {
      (mockRepo.findContext as jest.Mock).mockResolvedValue(null);

      const result = await service.getContext('unknown', 'unknown');

      expect(result).toBeNull();
    });

    it('should call findContext without actorId when not provided', async () => {
      const principalId = randomUUID();
      const tenantId = randomUUID();

      (mockRepo.findContext as jest.Mock).mockResolvedValue(makeMockContext());

      await service.getContext(principalId, tenantId);

      expect(mockRepo.findContext).toHaveBeenCalledWith(principalId, tenantId, undefined);
    });
  });

  describe('listMemberships', () => {
    it('should call listMemberships with correct principalId', async () => {
      const principalId = randomUUID();
      const memberships: RuntimeMembershipSummary[] = [
        { id: randomUUID(), tenantId: randomUUID(), principalId, status: 'ACTIVE', tenantType: 'ORGANIZATION', isolationTier: 'TENANT', runtimeStatus: 'ACTIVE' },
      ];

      (mockRepo.listMemberships as jest.Mock).mockResolvedValue(memberships);

      const result = await service.listMemberships(principalId);

      expect(mockRepo.listMemberships).toHaveBeenCalledWith(principalId);
      expect(result).toEqual(memberships);
    });

    it('should return empty array when no memberships', async () => {
      (mockRepo.listMemberships as jest.Mock).mockResolvedValue([]);

      const result = await service.listMemberships(randomUUID());

      expect(result).toHaveLength(0);
    });
  });

  describe('listActors', () => {
    it('should call listActors with correct membershipId', async () => {
      const membershipId = randomUUID();
      const actors: RuntimeActorSummary[] = [
        { id: randomUUID(), membershipId, actorType: 'USER', status: 'ACTIVE', isDefault: true },
      ];

      (mockRepo.listActors as jest.Mock).mockResolvedValue(actors);

      const result = await service.listActors(membershipId);

      expect(mockRepo.listActors).toHaveBeenCalledWith(membershipId);
      expect(result).toEqual(actors);
    });

    it('should return empty array when no actors', async () => {
      (mockRepo.listActors as jest.Mock).mockResolvedValue([]);

      const result = await service.listActors(randomUUID());

      expect(result).toHaveLength(0);
    });
  });

  describe('findActor', () => {
    it('should call findActor with correct parameters', async () => {
      const membershipId = randomUUID();
      const actorId = randomUUID();
      const actor: RuntimeActorSummary = { id: actorId, membershipId, actorType: 'USER', status: 'ACTIVE', isDefault: false };

      (mockRepo.findActor as jest.Mock).mockResolvedValue(actor);

      const result = await service.findActor(membershipId, actorId);

      expect(mockRepo.findActor).toHaveBeenCalledWith(membershipId, actorId);
      expect(result).toEqual(actor);
    });

    it('should return null when actor not found', async () => {
      (mockRepo.findActor as jest.Mock).mockResolvedValue(null);

      const result = await service.findActor(randomUUID(), randomUUID());

      expect(result).toBeNull();
    });
  });
});