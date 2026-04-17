import { WebhookService } from './webhook.service';
import { Webhook } from '../../../domain/entities/platform/webhook.entity';
import { App } from '../../../domain/entities/platform/app.entity';
import { NotFoundException, BadRequestException } from '@nestjs/common';

describe('WebhookService', () => {
  let webhookService: WebhookService;
  let webhookRepositoryMock: any;
  let appRepositoryMock: any;

  beforeEach(() => {
    webhookRepositoryMock = {
      save: jest.fn(),
      findByIdAndTenant: jest.fn(),
      findByAppId: jest.fn(),
      findByEvent: jest.fn(),
    };
    appRepositoryMock = {
      findByIdAndTenant: jest.fn(),
    };
    webhookService = new WebhookService(webhookRepositoryMock, appRepositoryMock);
  });

  it('should register a webhook successfully', async () => {
    appRepositoryMock.findByIdAndTenant.mockResolvedValue(new App({
      id: 'app-1',
      tenantId: 'tenant-1',
      clientId: 'client-1',
      name: 'Test App',
      type: 'public',
      redirectUris: [],
      allowedOrigins: []
    }));

    const webhook = await webhookService.registerWebhook('tenant-1', 'app-1', 'https://example.com/hook', ['user.created']);
    expect(webhook.url).toBe('https://example.com/hook');
    expect(webhook.secretKey).toMatch(/^whsec_/);
    expect(webhookRepositoryMock.save).toHaveBeenCalled();
  });

  it('should throw NotFoundException if app not found', async () => {
    appRepositoryMock.findByIdAndTenant.mockResolvedValue(null);
    await expect(webhookService.registerWebhook('tenant-1', 'app-1', 'https://example.com/hook', ['user.created']))
      .rejects.toThrow(NotFoundException);
  });

  it('should throw BadRequestException if URL is not HTTPS in production', async () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    appRepositoryMock.findByIdAndTenant.mockResolvedValue(new App({
      id: 'app-1',
      tenantId: 'tenant-1',
      clientId: 'client-1',
      name: 'Test App',
      type: 'public',
      redirectUris: [],
      allowedOrigins: []
    }));

    await expect(webhookService.registerWebhook('tenant-1', 'app-1', 'http://example.com/hook', ['user.created']))
      .rejects.toThrow(BadRequestException);

    process.env.NODE_ENV = originalEnv;
  });

  it('should update a webhook', async () => {
    const webhook = new Webhook({
      id: 'webhook-1',
      tenantId: 'tenant-1',
      appId: 'app-1',
      url: 'https://example.com/hook',
      events: ['user.created'],
      secretKey: 'sec',
      status: 'active',
      failureCount: 0
    });
    webhookRepositoryMock.findByIdAndTenant.mockResolvedValue(webhook);

    const updated = await webhookService.updateWebhook('webhook-1', 'tenant-1', undefined, undefined, 'suspended');
    expect(updated.status).toBe('suspended');
    expect(webhookRepositoryMock.save).toHaveBeenCalled();
  });
});
