import { OAuthController } from './oauth.controller';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';

describe('OAuthController', () => {
  let controller: OAuthController;
  let oauthServiceMock: any;
  let resMock: any;
  let reqMock: any;

  beforeEach(() => {
    oauthServiceMock = {
      authorize: jest.fn(),
      exchangeToken: jest.fn(),
      getUserInfo: jest.fn(),
      handleSocialLogin: jest.fn(),
    };
    resMock = {
      redirect: jest.fn(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    reqMock = {
      tenantId: 'tenant-1',
      user: { sub: 'user-1' },
    };
    controller = new OAuthController(oauthServiceMock as any);
  });

  // ... [Other tests remain the same, adding social callback tests]

  it('should handle social callback and detect collision', async () => {
    oauthServiceMock.handleSocialLogin.mockResolvedValue({
      userId: 'user-1',
      action: 'verification_required'
    });

    const result = await controller.socialCallback(reqMock, 'google', 'code123', 'state123');

    expect(result.verification_required).toBe(true);
    expect(result.message).toContain('verify your email');
    expect(result.userId).toBe('user-1');
  });

  it('should handle social callback successfully', async () => {
    oauthServiceMock.handleSocialLogin.mockResolvedValue({
      userId: 'user-2',
      action: 'created'
    });

    const result = await controller.socialCallback(reqMock, 'github', 'code123', 'state123');

    expect(result.success).toBe(true);
    expect(result.data?.action).toBe('created');
  });

  it('should throw if state is missing in callback', async () => {
    await expect(controller.socialCallback(reqMock, 'google', 'code123', '')).rejects.toThrow(BadRequestException);
  });
});
