import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { IDomainRepository } from '../../../../../domain/repositories/platform/domain.repository.interface';
import { Domain } from '../../../../../domain/entities/platform/domain.entity';

@Injectable()
export class MysqlDomainRepository implements IDomainRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async save(domain: Domain): Promise<void> {
    const query = `
      INSERT INTO domains (id, tenant_id, domain_name, status, dns_txt_record, created_at, verified_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        status = VALUES(status),
        verified_at = VALUES(verified_at)
    `;
    await this.pool.execute(query, [
      domain.id,
      domain.tenantId,
      domain.domainName,
      domain.status,
      domain.dnsTxtRecord,
      domain.createdAt,
      domain.verifiedAt,
    ]);
  }

  async findByIdAndTenant(id: string, tenantId: string): Promise<Domain | null> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM domains WHERE id = ? AND tenant_id = ?',
      [id, tenantId]
    );

    if (rows.length === 0) return null;
    return this.mapToEntity(rows[0]);
  }

  async findByDomainName(domainName: string): Promise<Domain | null> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM domains WHERE domain_name = ?',
      [domainName]
    );

    if (rows.length === 0) return null;
    return this.mapToEntity(rows[0]);
  }

  async findByTenant(tenantId: string): Promise<Domain[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM domains WHERE tenant_id = ? ORDER BY created_at DESC',
      [tenantId]
    );

    return rows.map((row: any) => this.mapToEntity(row));
  }

  private mapToEntity(row: any): Domain {
    return new Domain({
      id: row.id,
      tenantId: row.tenant_id,
      domainName: row.domain_name,
      status: row.status,
      dnsTxtRecord: row.dns_txt_record,
      createdAt: new Date(row.created_at),
      verifiedAt: row.verified_at ? new Date(row.verified_at) : null,
    });
  }
}
