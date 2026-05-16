import { TokenService } from './token.service';
import { ConfigService } from '@nestjs/config';
import { ITokenRepository } from '../ports/driven/i-token.repository';
import { Session } from '../../domain/aggregates/session.aggregate';
import { SessionId } from '../../domain/value-objects/session-id.vo';
import * as jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';

/**
 * Unit tests for TokenService.
 *
 * Covers:
 *   - Token minting (access, refresh, ID tokens)
 *   - Token parsing and validation
 *   - Key rotation
 */

function makeMockConfig(overrides: Record<string, unknown> = {}): ConfigService {
  const defaults = {
    JWT_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQChPjnku3k1GMw7\nTiImk5BhoV8aKX1Us5Nk8oa8HEr+hQCAeCGoRaiPj4i859z9fbhmsKy6LMrEHeFa\nRY9YHGEOg7i6KAFj5QcGEnQEVqAus6eAc1+vPu6cTlI72HxwFzILbKb/GEV5U+w2\ndjaWFKfv5ZQMqhbZHKnzcMML5hyDTCzR+3ooVbFlBeMCdDrydzt//os59OSvSoWX\nrueRZuU4G0izjGrWL0gxAnGI3fmyNFlHSk25w4KimWePN6grDgu1YgvwTh0ZuXEx\nVNNrvJPjjSXw1JyCsc3kQTQNlZ3RrUNLx72mr5PFCOKbeaOeu1BuT/dW186ap5z0\nZd7V4EBvAgMBAAECggEAB4GOOrZ6zSd4iRbj4m2CePZaUdf2RHqllRCbMrzocCfA\nibp4lUzvggYEWgg7J+EciUnr3duBnEE91oYgHFHEjONB4VyaZUw/QvTvSgJpq4g5\nIcgn1KXL1Xfp6RefV1fPwGtll2t0VH0SenM6AEuO3nfj/UuaYQSuFAM++S9USs0D\n6mxCanSUp++4CksfqJtKxgEzE+ctt4t4sOwKtYyL/eMGbLMPErm2VnHcK/kQI272\n8p0vgEk+f6rphajuPZIud/uCvW6VVTV0/xa7cJccrkO8hKQB8BWjAoX2B4bpAUNW\nOl9t/5JePwjtc09sfsXYTq4kHulzZ+7US9F0R6Uw/QKBgQDPEEJT766QiJiMgUsq\ntz0hC8MeFUBk0SrnAqiZj8GBLWkmmJ7MRibHM9+GUIiJLsjLVmvamczGiSZgvn9A\nS4FYmeP2KjA/CkZP5ozcM2+IK5pv4y1Es9FLcFYj9Beltv4Hl/+U7QSiKhzgDAP4\nwpvSXG8MCUuxwy7w5ItFEvcblQKBgQDHWb4AcW7pjEYuYTt41e+ZmNVz9aazMFO1\nbdGDbCZ1Daxb8X3FPGfLR35Nev7nRsHoy+UOGQjV85lGO3zZ1sJp5RPgWuSBdBdb\nCIqxpOuIJ9ndFR6hbscwOFfvAvBdpozfSL1RPYu+dIu5CLHAGdbf0xpmt+KZRzjE\nrXXtM/hK8wKBgDWCViGqxsnDAukMYIhhYgKwL3QOud1T0GpyXW+RnsfrHElFF4Ri\nfJLt7M2g8ifBV1J0utp69Fg6CRjnIatT19E1s5thu6YO2ay8P5qIEEJ4Qii35HLk\npSmBlkEkSxgf+fWsaffqaFAf4eZkNIKMiAgMqwXJQS5m6jKGXRc0l3chAoGAa1ns\nc5iiPaqIcJlzyVKLwI8JA3UZ3Az+RwlodflbjFVcp/aX4ArzagiJ/3dopWr5KUAD\njV/13iFcPPHz/eskrpnp5juMKho2KZOj/J3vKFctf1zMLerV4SW2VMOkZQo3elZV\nfNZD1sA0LeR8tBI2IDoyUXZc1GYCMAepJZ+C6fkCgYAx0KuCelpXt6xV4DaUtXIA\nHuUTcfNJ+p/PbhcM8WzuCuhDI9KQ8mCnKCkIGJ/0RQBXOB3OngvS5YfbPqQEXqCy\nmIW63idr5EP5KwCkq6tyA534QOrOPcGF0OpYozQsmxHzzWX/4U/hnB7T14hYmd69\nM0MdZVN1zuOHJKCU5WUvPQ==\n-----END PRIVATE KEY-----',
    JWT_PRIVATE_KEY_ENC: undefined as string | undefined,
    JWT_PUBLIC_KEY: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoT455Lt5NRjMO04iJpOQ\nYaFfGil9VLOTZPKGvBxK/oUAgHghqEWoj4+IvOfc/X24ZrCsuizKxB3hWkWPWBxh\nDoO4uigBY+UHBhJ0BFagLrOngHNfrz7unE5SO9h8cBcyC2ym/xhFeVPsNnY2lhSn\n7+WUDKoW2Ryp83DDC+Ycg0ws0ft6KFWxZQXjAnQ68nc7f/6LOfTkr0qFl67nkWbl\nOBtIs4xq1i9IMQJxiN35sjRZR0pNucOCoplnjzeoKw4LtWIL8E4dGblxMVTTa7yT\n440l8NScgrHN5EE0DZWd0a1DS8e9pq+TxQjim3mjnrtQbk/3VtfOmqec9GXe1eBA\nbwIDAQAB\n-----END PUBLIC KEY-----',
    JWT_KID: 'test-key-id',
    JWT_ISSUER: 'https://uicp.example.com',
    JWT_AUDIENCE: 'uicp-api',
    JWT_ACCESS_TOKEN_TTL_S: 900,
    JWT_REFRESH_TOKEN_TTL_S: 604800,
  };
  return {
    get: (key: string, defaultValue?: unknown) => overrides[key] ?? defaults[key as keyof typeof defaults] ?? defaultValue,
    getOrThrow: (key: string) => {
      const value = overrides[key] ?? defaults[key as keyof typeof defaults];
      if (value === undefined) throw new Error(`Missing config: ${key}`);
      return value;
    },
  } as ConfigService;
}

function makeMockTokenRepo(): ITokenRepository {
  return {
    isBlocklisted: jest.fn().mockResolvedValue(false),
    addToBlocklist: jest.fn().mockResolvedValue(undefined),
    saveRefreshToken: jest.fn().mockResolvedValue(undefined),
    findRefreshToken: jest.fn().mockResolvedValue(null),
    revokeToken: jest.fn().mockResolvedValue(undefined),
    rotateRefreshToken: jest.fn().mockResolvedValue(undefined),
    revokeFamily: jest.fn().mockResolvedValue(undefined),
    revokeAllFamiliesByUser: jest.fn().mockResolvedValue(undefined),
    getActiveJtisByUser: jest.fn().mockResolvedValue([]),
  };
}

function makeMockSession(overrides: Partial<Session> = {}): Session {
  const mock = {
    id: SessionId.from(randomUUID()),
    policyVersion: 'policy-v1',
    manifestVersion: 'manifest-v1',
    isMfaVerified: () => false,
    getMfaVerifiedAt: () => null,
    deviceFingerprint: undefined as string | undefined,
    ...overrides,
  } as Session;
  return mock;
}

describe('TokenService', () => {
  let service: TokenService;
  let mockConfig: ConfigService;
  let mockTokenRepo: ITokenRepository;

  beforeEach(() => {
    mockConfig = makeMockConfig();
    mockTokenRepo = makeMockTokenRepo();
    service = new TokenService(mockConfig, mockTokenRepo);
  });

  describe('mintAccessToken', () => {
    it('should mint a valid access token', async () => {
      const session = makeMockSession();

      const result = await service.mintAccessToken({
        principalId: randomUUID(),
        tenantId: randomUUID(),
        membershipId: randomUUID(),
        actorId: randomUUID(),
        session,
        capabilities: ['read', 'write'],
        roles: ['admin'],
        amr: ['pwd'],
      });

      expect(result.token).toBeDefined();
      expect(result.jti).toBeDefined();
      expect(result.expiresAt).toBeInstanceOf(Date);
    });

    it('should include session MFA state in token', async () => {
      const mfaSession = makeMockSession({
        isMfaVerified: () => true,
        getMfaVerifiedAt: () => new Date('2024-01-01'),
      });

      const result = await service.mintAccessToken({
        principalId: randomUUID(),
        tenantId: randomUUID(),
        membershipId: randomUUID(),
        actorId: randomUUID(),
        session: mfaSession,
        amr: ['mfa'],
      });

      const payload = service.parseAccessToken(result.token);
      expect(payload.mfa).toBe(true);
      expect(payload.vat).toBeDefined();
      expect(payload.acr).toBe('aal2');
    });

    it('should include policy/manifest versions from session', async () => {
      const session = makeMockSession({
        policyVersion: 'policy-v2',
        manifestVersion: 'manifest-v2',
      });

      const result = await service.mintAccessToken({
        principalId: randomUUID(),
        tenantId: randomUUID(),
        membershipId: randomUUID(),
        actorId: randomUUID(),
        session,
        amr: ['pwd'],
      });

      const payload = service.parseAccessToken(result.token);
      expect(payload.pv).toBe('policy-v2');
      expect(payload.mv).toBe('manifest-v2');
    });
  });

  describe('mintRefreshToken', () => {
    it('should mint a valid refresh token', async () => {
      const result = await service.mintRefreshToken(
        { value: randomUUID() } as any,
        { value: randomUUID() } as any,
        randomUUID(),
      );

      expect(result.token).toBeDefined();
      expect(result.jti).toBeDefined();
      expect(result.expiresAt).toBeInstanceOf(Date);
    });

    it('should include family ID in token', async () => {
      const familyId = randomUUID();
      const result = await service.mintRefreshToken(
        { value: randomUUID() } as any,
        { value: randomUUID() } as any,
        familyId,
      );

      const payload = service.parseRefreshToken(result.token);
      expect(payload.fid).toBe(familyId);
    });
  });

  describe('mintIdToken', () => {
    it('should mint a valid ID token', async () => {
      const result = await service.mintIdToken({
        sub: randomUUID(),
        aud: 'uicp-api',
        auth_time: Math.floor(Date.now() / 1000),
        acr: 'aal1',
      });

      expect(result.token).toBeDefined();
      expect(result.expiresAt).toBeInstanceOf(Date);
    });

    it('should include nonce when provided', async () => {
      const result = await service.mintIdToken({
        sub: randomUUID(),
        aud: 'uicp-api',
        auth_time: Math.floor(Date.now() / 1000),
        acr: 'aal1',
        nonce: 'test-nonce',
      });

      // ID tokens don't have a type field, so we decode directly
      const payload = jwt.decode(result.token) as Record<string, unknown>;
      expect(payload.nonce).toBe('test-nonce');
    });
  });

  describe('parseAccessToken', () => {
    it('should parse a valid access token', async () => {
      const session = makeMockSession();
      const result = await service.mintAccessToken({
        principalId: randomUUID(),
        tenantId: randomUUID(),
        membershipId: randomUUID(),
        actorId: randomUUID(),
        session,
        amr: ['pwd'],
      });

      const payload = service.parseAccessToken(result.token);
      expect(payload.type).toBe('access');
      expect(payload.sub).toBeDefined();
    });

    it('should throw on wrong token type', async () => {
      const refreshResult = await service.mintRefreshToken(
        { value: randomUUID() } as any,
        { value: randomUUID() } as any,
        randomUUID(),
      );

      // Refresh token has wrong audience for access token parsing
      expect(() => service.parseAccessToken(refreshResult.token)).toThrow();
    });
  });

  describe('parseRefreshToken', () => {
    it('should parse a valid refresh token', async () => {
      const result = await service.mintRefreshToken(
        { value: randomUUID() } as any,
        { value: randomUUID() } as any,
        randomUUID(),
      );

      const payload = service.parseRefreshToken(result.token);
      expect(payload.type).toBe('refresh');
      expect(payload.sub).toBeDefined();
    });

    it('should throw on wrong token type', async () => {
      const session = makeMockSession();
      const accessResult = await service.mintAccessToken({
        principalId: randomUUID(),
        tenantId: randomUUID(),
        membershipId: randomUUID(),
        actorId: randomUUID(),
        session,
        amr: ['pwd'],
      });

      // Access token has wrong audience for refresh token parsing
      expect(() => service.parseRefreshToken(accessResult.token)).toThrow();
    });
  });

  describe('validateAccessToken', () => {
    it('should validate a non-blocklisted token', async () => {
      const session = makeMockSession();
      const result = await service.mintAccessToken({
        principalId: randomUUID(),
        tenantId: randomUUID(),
        membershipId: randomUUID(),
        actorId: randomUUID(),
        session,
        amr: ['pwd'],
      });

      const payload = await service.validateAccessToken(result.token);
      expect(payload.jti).toBe(result.jti);
    });

    it('should reject a blocklisted token', async () => {
      const mockRepoWithBlocklist = {
        ...mockTokenRepo,
        isBlocklisted: jest.fn().mockResolvedValue(true),
      };
      const serviceWithBlocklist = new TokenService(mockConfig, mockRepoWithBlocklist);

      const session = makeMockSession();
      const result = await serviceWithBlocklist.mintAccessToken({
        principalId: randomUUID(),
        tenantId: randomUUID(),
        membershipId: randomUUID(),
        actorId: randomUUID(),
        session,
        amr: ['pwd'],
      });

      await expect(serviceWithBlocklist.validateAccessToken(result.token)).rejects.toThrow('TOKEN_BLOCKLISTED');
    });
  });

  describe('key rotation', () => {
    it('should rotate signing key', async () => {
      const oldKid = service.getKid();
      const newPrivateKey = '-----BEGIN RSA PRIVATE KEY-----\nnew-key\n-----END RSA PRIVATE KEY-----';
      const newPublicKey = '-----BEGIN PUBLIC KEY-----\nnew-key\n-----END PUBLIC KEY-----';
      const newKid = 'new-key-id';

      service.rotateSigningKey(newPrivateKey, newPublicKey, newKid);

      expect(service.getKid()).toBe(newKid);
      expect(service.getDeprecatedPublicKeys()).toContainEqual(expect.objectContaining({ kid: oldKid }));
    });
  });

  describe('getPublicKey / getKid', () => {
    it('should return public key', () => {
      const pubKey = service.getPublicKey();
      expect(pubKey).toContain('BEGIN PUBLIC KEY');
    });

    it('should return key ID', () => {
      const kid = service.getKid();
      expect(kid).toBe('test-key-id');
    });
  });
});