import { Injectable, Inject, NotFoundException, BadRequestException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { randomBytes } from 'crypto';
import { IDomainRepository, DOMAIN_REPOSITORY } from '../../../domain/repositories/platform/domain.repository.interface';
import { Domain } from '../../../domain/entities/platform/domain.entity';
import { IDnsAdapter, DNS_ADAPTER } from '../../../infrastructure/dns/dns.adapter';

@Injectable()
export class DomainService {
  constructor(
    @Inject(DOMAIN_REPOSITORY) private readonly domainRepository: IDomainRepository,
    @Inject(DNS_ADAPTER) private readonly dnsAdapter: IDnsAdapter,
  ) {}

  async registerDomain(tenantId: string, domainName: string): Promise<Domain> {
    // Normalize domain
    const normalizedDomain = domainName.toLowerCase().trim();

    // Check if domain is already registered globally
    const existing = await this.domainRepository.findByDomainName(normalizedDomain);
    if (existing) {
      if (existing.tenantId === tenantId) {
        return existing; // Idempotent for same tenant
      }
      throw new BadRequestException('Domain is already registered to another tenant');
    }

    const dnsTxtRecord = `uicp-verify=${randomBytes(16).toString('hex')}`;

    const domain = new Domain({
      id: uuidv4(),
      tenantId,
      domainName: normalizedDomain,
      status: 'pending',
      dnsTxtRecord,
    });

    await this.domainRepository.save(domain);
    return domain;
  }

  async listDomains(tenantId: string): Promise<Domain[]> {
    return this.domainRepository.findByTenant(tenantId);
  }

  async verifyDomain(id: string, tenantId: string): Promise<Domain> {
    const domain = await this.domainRepository.findByIdAndTenant(id, tenantId);
    if (!domain) {
      throw new NotFoundException('Domain not found');
    }

    if (domain.status === 'verified') {
      return domain;
    }

    // Perform DNS lookup
    const txtRecords = await this.dnsAdapter.resolveTxt(domain.domainName);

    // Flatten and search for the required record
    const hasRecord = txtRecords.some(chunk => chunk.join('').includes(domain.dnsTxtRecord));

    if (hasRecord) {
      domain.verify();
      await this.domainRepository.save(domain);
    } else {
      domain.fail();
      await this.domainRepository.save(domain);
      throw new BadRequestException(`Verification failed. Please ensure TXT record '${domain.dnsTxtRecord}' is configured for ${domain.domainName}.`);
    }

    return domain;
  }

  async removeDomain(id: string, tenantId: string): Promise<void> {
    // Note: We might want to just mark it deleted rather than physically removing,
    // or unlinking. For this MVP we will not physically delete, or we will just throw unsupported.
    throw new BadRequestException('Domain removal not yet implemented');
  }
}
