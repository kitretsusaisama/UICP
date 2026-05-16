import { Injectable, Inject } from '@nestjs/common';
import { Pool } from 'mysql2/promise';
import { IPlatformIdentityRepository } from '../../../../../domain/repositories/platform/platform-identity.repository.interface';
import { PlatformIdentity, PlatformIdentityStatus, MfaType } from '../../../../../domain/entities/platform/platform-identity.entity';

interface PlatformIdentityRow {
  id: string;
  email: string;
  display_name: string;
  password_hash: string | null;
  mfa_type: string;
  mfa_secret: string | null;
  mfa_enabled: boolean;
  status: string;
  risk_score: number;
  risk_level: string;
  last_login_at: Date | null;
  last_login_ip: string | null;
  last_login_device: string | null;
  created_at: Date;
  updated_at: Date;
}

@Injectable()
export class MysqlPlatformIdentityRepository implements IPlatformIdentityRepository {
  constructor(@Inject('MYSQL_POOL') private readonly pool: Pool) {}

  async findById(id: string): Promise<PlatformIdentity | null> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM platform_identities WHERE id = ?',
      [id]
    );
    if (rows.length === 0) return null;
    return this.rowToEntity(rows[0]);
  }

  async findByEmail(email: string): Promise<PlatformIdentity | null> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM platform_identities WHERE email = ?',
      [email]
    );
    if (rows.length === 0) return null;
    return this.rowToEntity(rows[0]);
  }

  async findAll(): Promise<PlatformIdentity[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM platform_identities ORDER BY created_at DESC'
    );
    return rows.map((row: any) => this.rowToEntity(row));
  }

  async findByStatus(status: string): Promise<PlatformIdentity[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM platform_identities WHERE status = ? ORDER BY created_at DESC',
      [status]
    );
    return rows.map((row: any) => this.rowToEntity(row));
  }

  async findByRiskLevel(level: string): Promise<PlatformIdentity[]> {
    const [rows]: any = await this.pool.execute(
      'SELECT * FROM platform_identities WHERE risk_level = ? ORDER BY risk_score DESC',
      [level]
    );
    return rows.map((row: any) => this.rowToEntity(row));
  }

  async save(entity: PlatformIdentity): Promise<PlatformIdentity> {
    const query = `
      INSERT INTO platform_identities (
        id, email, display_name, password_hash, mfa_type, mfa_secret,
        mfa_enabled, status, risk_score, risk_level, last_login_at,
        last_login_ip, last_login_device, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        display_name = VALUES(display_name),
        password_hash = VALUES(password_hash),
        mfa_type = VALUES(mfa_type),
        mfa_secret = VALUES(mfa_secret),
        mfa_enabled = VALUES(mfa_enabled),
        status = VALUES(status),
        risk_score = VALUES(risk_score),
        risk_level = VALUES(risk_level),
        last_login_at = VALUES(last_login_at),
        last_login_ip = VALUES(last_login_ip),
        last_login_device = VALUES(last_login_device),
        updated_at = VALUES(updated_at)
    `;

    await this.pool.execute(query, [
      entity.id,
      entity.email,
      entity.displayName,
      entity.passwordHash,
      entity.mfaType,
      entity.mfaSecret,
      entity.mfaEnabled,
      entity.status,
      entity.riskScore,
      entity.riskLevel,
      entity.lastLoginAt,
      entity.lastLoginIp,
      entity.lastLoginDevice,
      entity.createdAt,
      entity.updatedAt,
    ]);

    return entity;
  }

  async delete(id: string): Promise<void> {
    await this.pool.execute('DELETE FROM platform_identities WHERE id = ?', [id]);
  }

  private rowToEntity(row: PlatformIdentityRow): PlatformIdentity {
    return new PlatformIdentity({
      id: row.id,
      email: row.email,
      displayName: row.display_name,
      passwordHash: row.password_hash ?? undefined,
      mfaType: row.mfa_type as MfaType,
      mfaSecret: row.mfa_secret ?? undefined,
      mfaEnabled: row.mfa_enabled,
      status: row.status as PlatformIdentityStatus,
      riskScore: row.risk_score,
      riskLevel: row.risk_level as 'low' | 'medium' | 'high' | 'critical',
      lastLoginAt: row.last_login_at ?? undefined,
      lastLoginIp: row.last_login_ip ?? undefined,
      lastLoginDevice: row.last_login_device ?? undefined,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    });
  }
}