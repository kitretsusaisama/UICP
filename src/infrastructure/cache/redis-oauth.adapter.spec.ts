import { RedisOAuthAdapter, AuthorizationCodeData } from './redis-oauth.adapter';

describe('RedisOAuthAdapter', () => {
  let adapter: RedisOAuthAdapter;
  let cacheMock: any;

  beforeEach(() => {
    cacheMock = {
      set: jest.fn().mockResolvedValue('OK'),
      getdel: jest.fn(),
    };
    adapter = new RedisOAuthAdapter(cacheMock);
  });

  it('should store an authorization code with correct TTL', async () => {
    const data: AuthorizationCodeData = {
      code: 'abc',
      clientId: 'client-1',
      userId: 'user-1',
      tenantId: 'tenant-1',
      redirectUri: 'https://example.com',
      codeChallenge: 'chall',
      codeChallengeMethod: 'S256',
      scopes: ['openid'],
      expiresAt: Date.now() + 60000,
    };

    await adapter.storeAuthorizationCode(data);
    expect(cacheMock.set).toHaveBeenCalledWith(
      'oauth:code:abc',
      JSON.stringify(data),
      expect.any(Number)
    );
  });

  it('should atomically consume an authorization code using getdel', async () => {
    const data: AuthorizationCodeData = {
      code: 'abc',
      clientId: 'client-1',
      userId: 'user-1',
      tenantId: 'tenant-1',
      redirectUri: 'https://example.com',
      codeChallenge: 'chall',
      codeChallengeMethod: 'S256',
      scopes: ['openid'],
      expiresAt: Date.now() + 60000,
    };

    cacheMock.getdel.mockResolvedValue(JSON.stringify(data));

    const result = await adapter.consumeAuthorizationCode('abc');
    expect(result).toEqual(data);
    expect(cacheMock.getdel).toHaveBeenCalledWith('oauth:code:abc');
  });

  it('should return null if code is not found', async () => {
    cacheMock.getdel.mockResolvedValue(null);
    const result = await adapter.consumeAuthorizationCode('abc');
    expect(result).toBeNull();
  });
});
