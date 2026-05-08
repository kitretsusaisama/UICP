import { Domain } from '../../entities/platform/domain.entity';

export const DOMAIN_REPOSITORY = 'DOMAIN_REPOSITORY';

export interface IDomainRepository {
  save(domain: Domain): Promise<void>;
  findByIdAndTenant(id: string, tenantId: string): Promise<Domain | null>;
  findByDomainName(domainName: string): Promise<Domain | null>;
  findByTenant(tenantId: string): Promise<Domain[]>;
}
