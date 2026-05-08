import { MysqlAppRepository } from './mysql-app.repository';
import { App } from '../../../../../domain/entities/platform/app.entity';

describe('MysqlAppRepository', () => {
  let repository: MysqlAppRepository;
  let poolMock: any;

  beforeEach(() => {
    poolMock = {
      execute: jest.fn(),
    };
    repository = new MysqlAppRepository(poolMock);
  });

  it('should save an app', async () => {
    const app = new App({
      id: 'app-1',
      tenantId: 'tenant-1',
      clientId: 'client-1',
      name: 'Test App',
      type: 'public',
      redirectUris: ['https://example.com/callback'],
      allowedOrigins: ['https://example.com'],
    });

    await repository.save(app);
    expect(poolMock.execute).toHaveBeenCalled();
  });

  it('should find an app by id and tenant', async () => {
    poolMock.execute.mockResolvedValue([[{
      id: 'app-1',
      tenant_id: 'tenant-1',
      client_id: 'client-1',
      name: 'Test App',
      type: 'public',
      redirect_uris: JSON.stringify(['https://example.com/callback']),
      allowed_origins: JSON.stringify(['https://example.com']),
      created_at: new Date(),
      updated_at: new Date()
    }]]);

    const app = await repository.findByIdAndTenant('app-1', 'tenant-1');
    expect(app).toBeDefined();
    expect(app?.id).toBe('app-1');
    expect(app?.clientId).toBe('client-1');
    expect(app?.redirectUris).toEqual(['https://example.com/callback']);
  });

  it('should return null if app not found', async () => {
    poolMock.execute.mockResolvedValue([[]]);
    const app = await repository.findByIdAndTenant('app-1', 'tenant-1');
    expect(app).toBeNull();
  });
});
