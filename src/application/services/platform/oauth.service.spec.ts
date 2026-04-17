import { OAuthService } from './oauth.service';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { App } from '../../../domain/entities/platform/app.entity';
import { User } from '../../../domain/aggregates/user.aggregate';
import { Email } from '../../../domain/value-objects/email.vo';
import { TenantId } from '../../../domain/value-objects/tenant-id.vo';
import { UserId } from '../../../domain/value-objects/user-id.vo';
import { toEncryptedValue } from '../../../domain/entities/identity.entity';

describe('OAuthService', () => {
  let oauthService: OAuthService;
  let oauthCacheMock: any;
  let appRepositoryMock: any;
  let tokenServiceMock: any;
  let userRepoMock: any;
  let identityRepoMock: any;
  let encryptionPortMock: any;

  const validUserId = '11111111-1111-4111-8111-111111111111';
  const validTenantId = '22222222-2222-4222-8222-222222222222';

  beforeEach(() => {
    oauthCacheMock = {
      storeAuthorizationCode: jest.fn(),
      consumeAuthorizationCode: jest.fn(),
    };
    appRepositoryMock = {
      findByTenant: jest.fn(),
    };
    tokenServiceMock = {
      mintAccessToken: jest.fn().mockResolvedValue({ token: 'access_mock', jti: 'access_jti' }),
      mintRefreshToken: jest.fn().mockResolvedValue({ token: 'refresh_mock', jti: 'refresh_jti' }),
      mintIdToken: jest.fn().mockResolvedValue({ token: 'id_mock' }),
      validateAccessToken: jest.fn(),
    };
    userRepoMock = {
      findById: jest.fn(),
    };
    identityRepoMock = {
      findByHash: jest.fn(),
    };
    encryptionPortMock = {
      hmac: jest.fn().mockResolvedValue('hash_mock'),
    };
    oauthService = new OAuthService(
      oauthCacheMock,
      appRepositoryMock,
      userRepoMock,
      identityRepoMock,
      encryptionPortMock,
      tokenServiceMock
    );
  });

  // ... (keeping previous tests implicit for space, running social login tests)

  it('should successfully handle social login without collision', async () => {
    identityRepoMock.findByHash.mockResolvedValue(null);

    const result = await oauthService.handleSocialLogin({
      provider: 'google',
      providerUserId: 'g-123',
      email: 'new@example.com',
      emailVerified: true,
      tenantId: validTenantId
    });

    expect(result.action).toBe('created');
    expect(result.userId).toBeDefined();
  });

  it('should detect collision and require verification (no auto-merge)', async () => {
    const existingUser = User.createWithEmail({
      email: Email.create('exist@example.com'),
      tenantId: TenantId.from(validTenantId),
      emailEnc: toEncryptedValue('enc_mock'),
      emailHash: 'hash_mock',
    });
    // the repo mock returns the existing identity, not the user object here
    identityRepoMock.findByHash.mockResolvedValue(existingUser.getIdentity('EMAIL'));

    const result = await oauthService.handleSocialLogin({
      provider: 'github',
      providerUserId: 'gh-456',
      email: 'exist@example.com',
      emailVerified: true,
      tenantId: validTenantId
    });

    expect(result.action).toBe('verification_required');
    expect(result.userId).toBe(existingUser.getId().toString());
  });

  it('should treat unverified provider email as untrusted', async () => {
    await expect(oauthService.handleSocialLogin({
      provider: 'github',
      providerUserId: 'gh-456',
      email: 'unverified@example.com',
      emailVerified: false,
      tenantId: validTenantId
    })).rejects.toThrow(UnauthorizedException);
  });

  it('should require fallback input if no email from provider', async () => {
    await expect(oauthService.handleSocialLogin({
      provider: 'github',
      providerUserId: 'gh-456',
      tenantId: validTenantId
    })).rejects.toThrow(BadRequestException);
  });
});
