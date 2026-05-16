import { Inject, Injectable, Logger } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { ITenantOtpRiskPolicyRepository } from '../../../application/ports/driven/i-otp-risk.policy.port';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';
import { TenantIsolationGuard } from '../isolation/tenant-isolation-guard';

export interface RiskFactor {
  name: string;
  weight: number;
  value: number;
  contribution: number;
  description: string;
}

export interface RiskScore {
  score: number;
  level: 'LOW' | 'MEDIUM' | 'HIGH';
  factors: RiskFactor[];
  exceedsThreshold: boolean;
  policyApplied: string;
  blocked: boolean;
}

export interface RiskAssessmentInput {
  tenantId: string;
  identity: string;
  channel: string;
  provider: string;
  deviceFingerprint?: string;
  ipAddress?: string;
  geoCountry?: string;
  timestamp?: Date;
}

@Injectable()
export class TenantRiskScorer {
  private readonly logger = new Logger(TenantRiskScorer.name);

  constructor(
    private readonly isolationGuard: TenantIsolationGuard,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
    @Inject(INJECTION_TOKENS.OTP_RISK_POLICY_REPO)
    private readonly riskPolicyRepo: ITenantOtpRiskPolicyRepository,
  ) {}

  async scoreForTenant(input: RiskAssessmentInput): Promise<RiskScore> {
    const policy = await this.getPolicy(input.tenantId);

    const checks = await Promise.all([
      this.checkVelocity(input, policy),
      this.checkGeo(input, policy),
      this.checkDevice(input, policy),
      this.checkProvider(input, policy),
      this.checkTimePattern(input),
    ]);

    const totalScore = checks.reduce((sum, check) => sum + check.contribution, 0);

    const isHighRisk = totalScore > policy.riskThresholdHigh;
    const isMediumRisk = totalScore > policy.riskThresholdLow;

    let level: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
    if (isHighRisk) level = 'HIGH';
    else if (isMediumRisk) level = 'MEDIUM';

    const result: RiskScore = {
      score: Math.min(100, totalScore),
      level,
      factors: checks.map(c => ({
        name: c.name,
        weight: c.weight,
        value: c.value,
        contribution: c.contribution,
        description: c.description,
      })),
      exceedsThreshold: isHighRisk,
      policyApplied: 'tenant-configured',
      blocked: isHighRisk && policy.blockOnHighRisk,
    };

    if (result.blocked) {
      this.logger.warn({
        tenantId: input.tenantId,
        identity: input.identity,
        score: result.score,
        level: result.level,
      }, 'High risk detected - verification blocked');
    }

    return result;
  }

  async getPolicy(tenantId: string) {
    await this.isolationGuard.validateTenantAccess({
      tenantId,
      operation: 'VERIFY',
    });

    const cacheKey = `risk-policy:${tenantId}`;
    const cached = await this.cache.get(cacheKey);

    if (cached) {
      return JSON.parse(cached);
    }

    const policy = await this.riskPolicyRepo.findByTenantId(tenantId);

    const defaultPolicy = {
      tenantId,
      maxAttemptsPerHour: 10,
      maxAttemptsPerDay: 50,
      maxAttemptsPerIdentity: 5,
      allowedCountries: [] as string[],
      blockedCountries: [] as string[],
      blockUnknownGeo: false,
      requireDeviceFingerprint: false,
      blockUnknownDevices: false,
      maxDevicesPerIdentity: 10,
      trustedProviders: ['MSG91', 'Twilio', 'Firebase'],
      requireProviderVerification: true,
      riskThresholdLow: 30,
      riskThresholdHigh: 70,
      blockOnHighRisk: true,
    };

    const policyToCache = policy ?? defaultPolicy;
    await this.cache.set(cacheKey, JSON.stringify(policyToCache), 3600);

    return policyToCache;
  }

  private async checkVelocity(input: RiskAssessmentInput, policy: {
    maxAttemptsPerHour: number;
    maxAttemptsPerDay: number;
  }): Promise<RiskFactor> {
    const hourKey = `velocity:${input.tenantId}:${input.identity}:hour`;
    const dayKey = `velocity:${input.tenantId}:${input.identity}:day`;

    const hourCount = parseInt(await this.cache.get(hourKey) ?? '0', 10);
    const dayCount = parseInt(await this.cache.get(dayKey) ?? '0', 10);

    let value = 0;
    if (hourCount > policy.maxAttemptsPerHour) {
      value = 100;
    } else if (dayCount > policy.maxAttemptsPerDay) {
      value = 80;
    } else if (hourCount > policy.maxAttemptsPerHour / 2) {
      value = 50;
    }

    return {
      name: 'velocity',
      weight: 0.25,
      value,
      contribution: value * 0.25,
      description: `Hour: ${hourCount}/${policy.maxAttemptsPerHour}, Day: ${dayCount}/${policy.maxAttemptsPerDay}`,
    };
  }

  private async checkGeo(input: RiskAssessmentInput, policy: {
    allowedCountries: string[];
    blockedCountries: string[];
    blockUnknownGeo: boolean;
  }): Promise<RiskFactor> {
    const { geoCountry } = input;

    if (!geoCountry && policy.blockUnknownGeo) {
      return {
        name: 'geo',
        weight: 0.2,
        value: 60,
        contribution: 12,
        description: 'Unknown geographic location',
      };
    }

    if (geoCountry && policy.blockedCountries?.includes(geoCountry)) {
      return {
        name: 'geo',
        weight: 0.2,
        value: 100,
        contribution: 20,
        description: `Country ${geoCountry} is blocked`,
      };
    }

    if (geoCountry && policy.allowedCountries?.length > 0) {
      if (!policy.allowedCountries.includes(geoCountry)) {
        return {
          name: 'geo',
          weight: 0.2,
          value: 70,
          contribution: 14,
          description: `Country ${geoCountry} not in allowed list`,
        };
      }
    }

    return {
      name: 'geo',
      weight: 0.2,
      value: 0,
      contribution: 0,
      description: 'Geographic check passed',
    };
  }

  private async checkDevice(input: RiskAssessmentInput, policy: {
    requireDeviceFingerprint: boolean;
    blockUnknownDevices: boolean;
  }): Promise<RiskFactor> {
    const { deviceFingerprint, identity } = input;

    if (!deviceFingerprint) {
      if (policy.requireDeviceFingerprint) {
        return {
          name: 'device',
          weight: 0.15,
          value: 50,
          contribution: 7.5,
          description: 'Device fingerprint required but not provided',
        };
      }
      return {
        name: 'device',
        weight: 0.15,
        value: 0,
        contribution: 0,
        description: 'No fingerprint - allowed',
      };
    }

    const deviceKey = `device:${input.tenantId}:${identity}:${deviceFingerprint}`;
    const isKnown = await this.cache.get(deviceKey);

    if (!isKnown && policy.blockUnknownDevices) {
      return {
        name: 'device',
        weight: 0.15,
        value: 70,
        contribution: 10.5,
        description: 'Unknown device - blocked',
      };
    }

    return {
      name: 'device',
      weight: 0.15,
      value: isKnown ? 5 : 30,
      contribution: isKnown ? 0.75 : 4.5,
      description: isKnown ? 'Known device' : 'New device',
    };
  }

  private async checkProvider(input: RiskAssessmentInput, policy: {
    trustedProviders: string[];
  }): Promise<RiskFactor> {
    const { provider } = input;

    if (policy.trustedProviders?.length > 0) {
      if (!policy.trustedProviders.includes(provider)) {
        return {
          name: 'provider',
          weight: 0.2,
          value: 60,
          contribution: 12,
          description: `Provider ${provider} not in trusted list`,
        };
      }
    }

    return {
      name: 'provider',
      weight: 0.2,
      value: 0,
      contribution: 0,
      description: 'Provider trusted',
    };
  }

  private async checkTimePattern(input: RiskAssessmentInput): Promise<RiskFactor> {
    const hour = (input.timestamp ?? new Date()).getHours();

    if (hour >= 2 && hour <= 5) {
      return {
        name: 'time',
        weight: 0.2,
        value: 40,
        contribution: 8,
        description: 'Unusual hour (2AM-5AM)',
      };
    }

    return {
      name: 'time',
      weight: 0.2,
      value: 0,
      contribution: 0,
      description: 'Normal hours',
    };
  }

  async recordVelocity(tenantId: string, identity: string): Promise<void> {
    const hourKey = `velocity:${tenantId}:${identity}:hour`;
    const dayKey = `velocity:${tenantId}:${identity}:day`;

    const hourCount = await this.cache.incr(hourKey);
    if (hourCount === 1) {
      await this.cache.expire(hourKey, 3600);
    }

    const dayCount = await this.cache.incr(dayKey);
    if (dayCount === 1) {
      await this.cache.expire(dayKey, 86400);
    }
  }

  async recordDevice(tenantId: string, identity: string, deviceFingerprint: string): Promise<void> {
    if (!deviceFingerprint) return;

    const deviceKey = `device:${tenantId}:${identity}:${deviceFingerprint}`;
    await this.cache.set(deviceKey, '1', 86400 * 30);
  }
}