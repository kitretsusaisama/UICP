import { MysqlWebhookRepository } from './mysql-webhook.repository';
import { Webhook } from '../../../../../domain/entities/platform/webhook.entity';

describe('MysqlWebhookRepository', () => {
  let repository: MysqlWebhookRepository;
  let poolMock: any;

  beforeEach(() => {
    poolMock = {
      execute: jest.fn(),
    };
    repository = new MysqlWebhookRepository(poolMock);
  });

  it('should save a webhook', async () => {
    const webhook = new Webhook({
      id: 'webhook-1',
      tenantId: 'tenant-1',
      appId: 'app-1',
      url: 'https://example.com/webhook',
      events: ['user.created'],
      secretKey: 'sec_123',
      status: 'active',
      failureCount: 0
    });

    await repository.save(webhook);
    expect(poolMock.execute).toHaveBeenCalled();
  });

  it('should find webhook by id', async () => {
    poolMock.execute.mockResolvedValue([[{
      id: 'webhook-1',
      tenant_id: 'tenant-1',
      app_id: 'app-1',
      url: 'https://example.com/webhook',
      events: JSON.stringify(['user.created']),
      secret_key: 'sec_123',
      status: 'active',
      failure_count: 0,
      created_at: new Date()
    }]]);

    const webhook = await repository.findByIdAndTenant('webhook-1', 'tenant-1');
    expect(webhook).toBeDefined();
    expect(webhook?.url).toBe('https://example.com/webhook');
  });

  it('should find webhooks by app id', async () => {
    poolMock.execute.mockResolvedValue([[{
      id: 'webhook-1',
      tenant_id: 'tenant-1',
      app_id: 'app-1',
      url: 'https://example.com/webhook',
      events: JSON.stringify(['user.created']),
      secret_key: 'sec_123',
      status: 'active',
      failure_count: 0,
      created_at: new Date()
    }]]);

    const webhooks = await repository.findByAppId('app-1', 'tenant-1');
    expect(webhooks).toHaveLength(1);
  });

  it('should find webhooks by event', async () => {
    poolMock.execute.mockResolvedValue([[{
      id: 'webhook-1',
      tenant_id: 'tenant-1',
      app_id: 'app-1',
      url: 'https://example.com/webhook',
      events: JSON.stringify(['user.created']),
      secret_key: 'sec_123',
      status: 'active',
      failure_count: 0,
      created_at: new Date()
    }]]);

    const webhooks = await repository.findByEvent('tenant-1', 'user.created');
    expect(webhooks).toHaveLength(1);
    expect(poolMock.execute).toHaveBeenCalledWith(expect.any(String), ['tenant-1', '"user.created"']);
  });
});
