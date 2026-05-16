import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { IPlatformIdentityRepository } from '../../../domain/repositories/platform/platform-identity.repository.interface';
import { PlatformIdentity, PlatformIdentityProps, PlatformIdentityStatus, MfaType } from '../../../domain/entities/platform/platform-identity.entity';

export interface CreatePlatformIdentityInput {
  email: string;
  displayName: string;
  passwordHash?: string;
  mfaType?: MfaType;
  mfaSecret?: string;
}

export interface UpdatePlatformIdentityInput {
  displayName?: string;
  mfaType?: MfaType;
  mfaSecret?: string;
  mfaEnabled?: boolean;
}

@Injectable()
export class PlatformIdentityService {
  constructor(private readonly platformIdentityRepository: IPlatformIdentityRepository) {}

  async create(input: CreatePlatformIdentityInput): Promise<PlatformIdentity> {
    const existing = await this.platformIdentityRepository.findByEmail(input.email);
    if (existing) {
      throw new BadRequestException('Platform identity with this email already exists');
    }

    const identity = PlatformIdentity.create({
      email: input.email,
      displayName: input.displayName,
      passwordHash: input.passwordHash,
      mfaType: input.mfaType ?? MfaType.TOTP,
      mfaSecret: input.mfaSecret,
      mfaEnabled: !!input.mfaSecret,
      status: PlatformIdentityStatus.ACTIVE,
    });

    return this.platformIdentityRepository.save(identity);
  }

  async getById(id: string): Promise<PlatformIdentity> {
    const identity = await this.platformIdentityRepository.findById(id);
    if (!identity) {
      throw new NotFoundException('Platform identity not found');
    }
    return identity;
  }

  async getByEmail(email: string): Promise<PlatformIdentity | null> {
    return this.platformIdentityRepository.findByEmail(email);
  }

  async listAll(): Promise<PlatformIdentity[]> {
    return this.platformIdentityRepository.findAll();
  }

  async listByStatus(status: PlatformIdentityStatus): Promise<PlatformIdentity[]> {
    return this.platformIdentityRepository.findByStatus(status);
  }

  async listByRiskLevel(level: 'low' | 'medium' | 'high' | 'critical'): Promise<PlatformIdentity[]> {
    return this.platformIdentityRepository.findByRiskLevel(level);
  }

  async update(id: string, input: UpdatePlatformIdentityInput): Promise<PlatformIdentity> {
    const identity = await this.getById(id);

    const props: PlatformIdentityProps = {
      id: identity.id,
      email: identity.email,
      displayName: input.displayName ?? identity.displayName,
      passwordHash: identity.passwordHash ?? undefined,
      mfaType: input.mfaType ?? identity.mfaType,
      mfaSecret: input.mfaSecret ?? identity.mfaSecret ?? undefined,
      mfaEnabled: input.mfaEnabled ?? identity.mfaEnabled,
      status: identity.status,
      riskScore: identity.riskScore,
      riskLevel: identity.riskLevel,
      lastLoginAt: identity.lastLoginAt ?? undefined,
      lastLoginIp: identity.lastLoginIp ?? undefined,
      lastLoginDevice: identity.lastLoginDevice ?? undefined,
      createdAt: identity.createdAt,
      updatedAt: new Date(),
    };

    const updated = new PlatformIdentity(props);
    return this.platformIdentityRepository.save(updated);
  }

  async recordLogin(id: string, ip: string, device: string): Promise<PlatformIdentity> {
    const identity = await this.getById(id);
    identity.updateLastLogin(ip, device);
    return this.platformIdentityRepository.save(identity);
  }

  async updateRiskScore(id: string, score: number, level: 'low' | 'medium' | 'high' | 'critical'): Promise<PlatformIdentity> {
    const identity = await this.getById(id);
    identity.updateRiskScore(score, level);
    return this.platformIdentityRepository.save(identity);
  }

  async suspend(id: string, reason: string): Promise<PlatformIdentity> {
    const identity = await this.getById(id);
    identity.suspend(reason);
    return this.platformIdentityRepository.save(identity);
  }

  async reactivate(id: string): Promise<PlatformIdentity> {
    const identity = await this.getById(id);
    identity.reactivate();
    return this.platformIdentityRepository.save(identity);
  }

  async deactivate(id: string): Promise<void> {
    const identity = await this.getById(id);
    identity.deactivate();
    await this.platformIdentityRepository.save(identity);
  }

  async setPassword(id: string, passwordHash: string): Promise<PlatformIdentity> {
    const identity = await this.getById(id);
    identity.setPassword(passwordHash);
    return this.platformIdentityRepository.save(identity);
  }

  async setupMfa(id: string, secret: string, type: MfaType): Promise<PlatformIdentity> {
    const identity = await this.getById(id);
    identity.updateMfa(secret, type);
    return this.platformIdentityRepository.save(identity);
  }
}