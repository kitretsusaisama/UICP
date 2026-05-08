import { MysqlDomainRepository } from './mysql-domain.repository';
import { Domain } from '../../../../../domain/entities/platform/domain.entity';

describe('MysqlDomainRepository', () => {
  let repository: MysqlDomainRepository;
  let poolMock: any;

  beforeEach(() => {
    poolMock = {
      execute: jest.fn(),
    };
    repository = new MysqlDomainRepository(poolMock);
  });

  it('should save a domain', async () => {
    const domain = new Domain({
      id: 'domain-1',
      tenantId: 'tenant-1',
      domainName: 'example.com',
      status: 'pending',
      dnsTxtRecord: 'uicp-verify=123',
    });

    await repository.save(domain);
    expect(poolMock.execute).toHaveBeenCalled();
  });

  it('should find a domain by id and tenant', async () => {
    poolMock.execute.mockResolvedValue([[{
      id: 'domain-1',
      tenant_id: 'tenant-1',
      domain_name: 'example.com',
      status: 'pending',
      dns_txt_record: 'uicp-verify=123',
      created_at: new Date(),
      verified_at: null
    }]]);

    const domain = await repository.findByIdAndTenant('domain-1', 'tenant-1');
    expect(domain).toBeDefined();
    expect(domain?.domainName).toBe('example.com');
  });

  it('should find a domain by name', async () => {
    poolMock.execute.mockResolvedValue([[{
      id: 'domain-1',
      tenant_id: 'tenant-1',
      domain_name: 'example.com',
      status: 'pending',
      dns_txt_record: 'uicp-verify=123',
      created_at: new Date(),
      verified_at: null
    }]]);

    const domain = await repository.findByDomainName('example.com');
    expect(domain).toBeDefined();
    expect(domain?.id).toBe('domain-1');
  });

  it('should find domains by tenant', async () => {
    poolMock.execute.mockResolvedValue([[{
      id: 'domain-1',
      tenant_id: 'tenant-1',
      domain_name: 'example.com',
      status: 'pending',
      dns_txt_record: 'uicp-verify=123',
      created_at: new Date(),
      verified_at: null
    }]]);

    const domains = await repository.findByTenant('tenant-1');
    expect(domains).toHaveLength(1);
    expect(domains[0]?.domainName).toBe('example.com');
  });
});
