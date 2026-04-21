import { DomainService } from './domain.service';
import { Domain } from '../../../domain/entities/platform/domain.entity';
import { BadRequestException, NotFoundException } from '@nestjs/common';

describe('DomainService', () => {
  let domainService: DomainService;
  let domainRepositoryMock: any;
  let dnsAdapterMock: any;

  beforeEach(() => {
    domainRepositoryMock = {
      save: jest.fn(),
      findByDomainName: jest.fn(),
      findByIdAndTenant: jest.fn(),
      findByTenant: jest.fn(),
    };
    dnsAdapterMock = {
      resolveTxt: jest.fn(),
    };
    domainService = new DomainService(domainRepositoryMock, dnsAdapterMock);
  });

  it('should register a new domain', async () => {
    domainRepositoryMock.findByDomainName.mockResolvedValue(null);

    const domain = await domainService.registerDomain('tenant-1', 'example.com');
    expect(domain.domainName).toBe('example.com');
    expect(domain.status).toBe('pending');
    expect(domain.dnsTxtRecord).toMatch(/^uicp-verify=/);
    expect(domainRepositoryMock.save).toHaveBeenCalledWith(domain);
  });

  it('should throw BadRequestException if domain registered by another tenant', async () => {
    domainRepositoryMock.findByDomainName.mockResolvedValue(new Domain({
      id: 'd-1',
      tenantId: 'tenant-2',
      domainName: 'example.com',
      status: 'verified',
      dnsTxtRecord: '123'
    }));

    await expect(domainService.registerDomain('tenant-1', 'example.com'))
      .rejects.toThrow(BadRequestException);
  });

  it('should return existing domain if registered by same tenant', async () => {
    const existing = new Domain({
      id: 'd-1',
      tenantId: 'tenant-1',
      domainName: 'example.com',
      status: 'pending',
      dnsTxtRecord: '123'
    });
    domainRepositoryMock.findByDomainName.mockResolvedValue(existing);

    const domain = await domainService.registerDomain('tenant-1', 'example.com');
    expect(domain).toBe(existing);
  });

  it('should verify a domain successfully', async () => {
    const domain = new Domain({
      id: 'd-1',
      tenantId: 'tenant-1',
      domainName: 'example.com',
      status: 'pending',
      dnsTxtRecord: 'uicp-verify=abc'
    });
    domainRepositoryMock.findByIdAndTenant.mockResolvedValue(domain);
    dnsAdapterMock.resolveTxt.mockResolvedValue([['v=spf1'], ['uicp-verify=abc']]);

    await domainService.verifyDomain('d-1', 'tenant-1');
    expect(domain.status).toBe('verified');
    expect(domain.verifiedAt).toBeDefined();
    expect(domainRepositoryMock.save).toHaveBeenCalledWith(domain);
  });

  it('should fail verification if TXT record is missing', async () => {
    const domain = new Domain({
      id: 'd-1',
      tenantId: 'tenant-1',
      domainName: 'example.com',
      status: 'pending',
      dnsTxtRecord: 'uicp-verify=abc'
    });
    domainRepositoryMock.findByIdAndTenant.mockResolvedValue(domain);
    dnsAdapterMock.resolveTxt.mockResolvedValue([['v=spf1']]);

    await expect(domainService.verifyDomain('d-1', 'tenant-1'))
      .rejects.toThrow(BadRequestException);

    expect(domain.status).toBe('failed');
    expect(domainRepositoryMock.save).toHaveBeenCalledWith(domain);
  });
});
