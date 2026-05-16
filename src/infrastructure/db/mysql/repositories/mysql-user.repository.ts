import { Inject, Injectable } from '@nestjs/common';
import { User } from '../../../../domain/entities/user.entity';
import { IUserRepository } from '../../../../domain/repositories/user.repository.interface';
import { MYSQL_POOL, DbPool } from '../mysql.module';
import { uuidToBuffer, bufferToUuid } from '../uuid-utils';

interface UserRow {
  id: Buffer;
  tenant_id: Buffer;
  email: string | null;
  phone: string | null;
  created_at: Date;
  updated_at: Date;
}

@Injectable()
export class MysqlUserRepository implements IUserRepository {
  constructor(@Inject(MYSQL_POOL) private readonly pool: DbPool) {}

  async save(user: User): Promise<void> {
    await this.pool.execute(
      `INSERT INTO users (id, tenant_id, email, phone, created_at, updated_at)
       VALUES (?, ?, ?, ?, NOW(), NOW())
       ON DUPLICATE KEY UPDATE
         email = VALUES(email),
         phone = VALUES(phone),
         updated_at = NOW()`,
      [
        uuidToBuffer(user.id),
        uuidToBuffer(user.tenantId),
        user.email ?? null,
        user.phone ?? null,
      ],
    );
  }

  async findById(id: string): Promise<User | null> {
    const [rows] = await this.pool.execute<UserRow[]>(
      `SELECT id, tenant_id, email, phone, created_at, updated_at
       FROM users WHERE id = ? LIMIT 1`,
      [uuidToBuffer(id)],
    );
    const row = rows[0];
    return row ? this.rowToUser(row) : null;
  }

  async findByEmail(email: string): Promise<User | null> {
    const [rows] = await this.pool.execute<UserRow[]>(
      `SELECT id, tenant_id, email, phone, created_at, updated_at
       FROM users WHERE email = ? LIMIT 1`,
      [email],
    );
    const row = rows[0];
    return row ? this.rowToUser(row) : null;
  }

  async findByPhone(phone: string): Promise<User | null> {
    const [rows] = await this.pool.execute<UserRow[]>(
      `SELECT id, tenant_id, email, phone, created_at, updated_at
       FROM users WHERE phone = ? LIMIT 1`,
      [phone],
    );
    const row = rows[0];
    return row ? this.rowToUser(row) : null;
  }

  private rowToUser(row: UserRow): User {
    return new User(
      bufferToUuid(row.id),
      bufferToUuid(row.tenant_id),
      row.email ?? undefined,
      row.phone ?? undefined,
    );
  }
}