import { Injectable, Inject, NotFoundException } from '@nestjs/common';
import { IUserRepository } from '../../../../src/domain/repositories/user.repository.interface';
import { User } from '../../../../src/domain/entities/user.entity';
import { Pool } from 'mysql2/promise';
import { Consistency } from '../consistency.enum';

@Injectable()
export class MysqlUserRepository implements IUserRepository {
  constructor(
    @Inject('WRITER_POOL') private readonly writerPool: Pool,
    @Inject('READER_POOL') private readonly readerPool: Pool
  ) {}

  private getPool(consistency: Consistency = Consistency.EVENTUAL): Pool {
    return consistency === Consistency.STRONG ? this.writerPool : this.readerPool;
  }

  async save(user: User): Promise<void> {
    const query = `
      INSERT INTO users (id, email, phone, status, mfa_enabled, roles, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        status = VALUES(status),
        mfa_enabled = VALUES(mfa_enabled),
        roles = VALUES(roles),
        updated_at = VALUES(updated_at)
    `;
    const params = [
      user.id,
      user.email,
      user.phone,
      user.status,
      user.mfaEnabled,
      JSON.stringify(user.roles),
      user.createdAt,
      user.updatedAt
    ];

    await this.writerPool.execute(query, params);
  }

  async findById(id: string, consistency: Consistency = Consistency.EVENTUAL): Promise<User | null> {
    const pool = this.getPool(consistency);
    const [rows]: any = await pool.query('SELECT * FROM users WHERE id = ? LIMIT 1', [id]);
    return this.mapToEntity(rows[0]);
  }

  async findByEmail(email: string, consistency: Consistency = Consistency.EVENTUAL): Promise<User | null> {
    const pool = this.getPool(consistency);
    const [rows]: any = await pool.query('SELECT * FROM users WHERE email = ? LIMIT 1', [email]);
    return this.mapToEntity(rows[0]);
  }

  async findByPhone(phone: string, consistency: Consistency = Consistency.EVENTUAL): Promise<User | null> {
    const pool = this.getPool(consistency);
    const [rows]: any = await pool.query('SELECT * FROM users WHERE phone = ? LIMIT 1', [phone]);
    return this.mapToEntity(rows[0]);
  }

  private mapToEntity(row: any): User | null {
    if (!row) return null;
    const user = new User(row.id, row.email, row.phone);
    user.status = row.status;
    user.mfaEnabled = !!row.mfa_enabled;
    user.roles = typeof row.roles === 'string' ? JSON.parse(row.roles) : row.roles || [];
    user.createdAt = row.created_at;
    user.updatedAt = row.updated_at;
    return user;
  }
}
