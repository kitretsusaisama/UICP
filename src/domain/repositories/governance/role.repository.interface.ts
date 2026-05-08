import { Role } from '../../entities/governance/role.entity';

export const ROLE_REPOSITORY = 'ROLE_REPOSITORY';

export interface IRoleRepository {
  save(role: Role): Promise<void>;
  findByIdAndTenant(id: string, tenantId: string): Promise<Role | null>;
  findByTenant(tenantId: string): Promise<Role[]>;
  delete(id: string, tenantId: string): Promise<void>;
}
