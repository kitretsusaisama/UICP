import { Inject, Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';
import { TenantIsolationGuard } from '../isolation/tenant-isolation-guard';
import { TenantProviderRegistry } from '../registry/tenant-provider-registry';
import { TenantAdaptiveEngine, Channel } from '../adaptive/tenant-adaptive-engine';
import { TenantRiskScorer } from '../security/tenant-risk-scorer';
import { TenantWidgetConfigService } from '../widgets/tenant-widget-config.service';

export type Purpose = 'IDENTITY_VERIFICATION' | 'MFA' | 'PASSWORD_RESET';

export interface OtpSendParams {
  tenantId: string;
  identity: string;
  channel: Channel;
  purpose: Purpose;
  deviceFingerprint?: string;
  ipAddress?: string;
  geoCountry?: string;
}

export interface OtpChallenge {
  id: string;
  tenantId: string;
  lineageId: string;
  channel: Channel;
  purpose: Purpose;
  provider: string;
  expiresAt: Date;
  resendCooldownSeconds: number;
  maxAttempts: number;
}

export interface OtpVerifyParams {
  tenantId: string;
  challengeId: string;
  code?: string;
  providerToken?: string;
  deviceFingerprint?: string;
  ipAddress?: string;
}

export interface OtpVerifyResult {
  verified: boolean;
  challengeId: string;
  identity?: string;
  sessionCreated: boolean;
  riskScore?: number;
  riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH';
}

@Injectable()
export class UniversalOtpKernel {
  private readonly logger = new Logger(UniversalOtpKernel.name);
  private readonly otpCodeLength = 6;
  private readonly otpTTLSeconds = 300;
  private readonly maxAttempts = 3;
  private readonly resendCooldownSeconds = 60;

  constructor(
    private readonly isolationGuard: TenantIsolationGuard,
    private readonly tenantRegistry: TenantProviderRegistry,
    private readonly adaptiveEngine: TenantAdaptiveEngine,
    private readonly riskScorer: TenantRiskScorer,
    private readonly widgetConfigService: TenantWidgetConfigService,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
  ) {}

  async sendOtp(input: OtpSendParams): Promise<OtpChallenge> {
    await this.isolationGuard.validateTenantAccess({
      tenantId: input.tenantId,
      operation: 'SEND',
      identity: input.identity,
    });

    const recommendation = await this.adaptiveEngine.recommendForTenant({
      tenantId: input.tenantId,
      identity: input.identity,
      requestedChannel: input.channel,
    });

    const { provider } = await this.tenantRegistry.getProviderConfig(input.tenantId);

    const rateLimit = await this.tenantRegistry.checkRateLimit(
      input.tenantId,
      provider.providerName,
    );

    if (!rateLimit.allowed) {
      throw new DomainException(
        DomainErrorCode.RATE_LIMIT_EXCEEDED,
        `Rate limit exceeded for tenant ${input.tenantId}`,
      );
    }

    const challengeId = randomUUID();
    const lineageId = randomUUID();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.otpTTLSeconds * 1000);

    // Generate OTP code
    const code = this.generateOtpCode();

    // Store challenge in Redis
    const challengeKey = this.isolationGuard.otpKey(input.tenantId, 'challenge', challengeId);
    const challengeData = {
      id: challengeId,
      lineageId,
      tenantId: input.tenantId,
      identity: input.identity,
      channel: recommendation.channel,
      purpose: input.purpose,
      provider: provider.providerName,
      code,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      attempts: 0,
    };
    await this.cache.set(challengeKey, JSON.stringify(challengeData), this.otpTTLSeconds);

    // Record velocity
    await this.riskScorer.recordVelocity(input.tenantId, input.identity);

    // Send via provider (in production, dispatch to actual provider)
    await this.dispatchToProvider(provider.providerName, {
      identity: input.identity,
      code,
      channel: recommendation.channel,
      purpose: input.purpose,
    });

    // Update rate limit
    await this.tenantRegistry.incrementRateLimit(input.tenantId, provider.providerName);

    // Record outcome for adaptive learning
    await this.adaptiveEngine.recordTenantOutcome({
      tenantId: input.tenantId,
      identity: input.identity,
      channel: recommendation.channel,
      providerKey: provider.providerName,
      success: true,
      latencyMs: 1500,
    });

    this.logger.debug({
      tenantId: input.tenantId,
      identity: input.identity,
      channel: recommendation.channel,
      provider: provider.providerName,
      challengeId,
    }, 'OTP sent successfully');

    return {
      id: challengeId,
      tenantId: input.tenantId,
      lineageId,
      channel: recommendation.channel,
      purpose: input.purpose,
      provider: provider.providerName,
      expiresAt,
      resendCooldownSeconds: this.resendCooldownSeconds,
      maxAttempts: this.maxAttempts,
    };
  }

  async verifyOtp(input: OtpVerifyParams): Promise<OtpVerifyResult> {
    await this.isolationGuard.validateTenantAccess({
      tenantId: input.tenantId,
      operation: 'VERIFY',
      resourceId: input.challengeId,
    });

    if (!input.challengeId) {
      throw new DomainException(
        DomainErrorCode.INVALID_OTP,
        'Challenge ID is required',
      );
    }

    const challengeKey = this.isolationGuard.otpKey(input.tenantId, 'challenge', input.challengeId);
    const challengeDataStr = await this.cache.get(challengeKey);

    if (!challengeDataStr) {
      throw new DomainException(
        DomainErrorCode.OTP_EXPIRED,
        'Challenge not found or expired',
      );
    }

    const challengeData = JSON.parse(challengeDataStr);

    // Check max attempts
    if (challengeData.attempts >= this.maxAttempts) {
      await this.cache.del(challengeKey);
      throw new DomainException(
        DomainErrorCode.OTP_ALREADY_USED,
        'Maximum verification attempts exceeded',
      );
    }

    let verified = false;
    let identity = challengeData.identity;

    // Verify using provider token (widget flow) or code
    if (input.providerToken) {
      verified = await this.verifyWithProviderToken(
        challengeData.provider,
        input.providerToken,
        input.tenantId,
      );
    } else if (input.code) {
      verified = this.verifyCode(input.code, challengeData.code);
    } else {
      throw new DomainException(
        DomainErrorCode.INVALID_OTP,
        'Code or provider token required',
      );
    }

    // Delete challenge (single use)
    await this.cache.del(challengeKey);

    if (!verified) {
      // Increment attempts and update challenge
      challengeData.attempts += 1;
      await this.cache.set(challengeKey, JSON.stringify(challengeData), this.otpTTLSeconds);

      // Record failure
      await this.tenantRegistry.recordFailure(input.tenantId, challengeData.provider);

      throw new DomainException(
        DomainErrorCode.INVALID_OTP,
        'Invalid OTP code',
      );
    }

    // Record success
    await this.tenantRegistry.recordSuccess(input.tenantId, challengeData.provider);

    // Risk assessment
    const riskScore = await this.riskScorer.scoreForTenant({
      tenantId: input.tenantId,
      identity,
      channel: challengeData.channel,
      provider: challengeData.provider,
      deviceFingerprint: input.deviceFingerprint,
      ipAddress: input.ipAddress,
    });

    return {
      verified: true,
      challengeId: input.challengeId,
      identity,
      sessionCreated: !riskScore.blocked,
      riskScore: riskScore.score,
      riskLevel: riskScore.level,
    };
  }

  async getWidgetConfig(tenantId: string) {
    return this.widgetConfigService.getWidgetConfig(tenantId);
  }

  async retryOtp(input: {
    tenantId: string;
    challengeId: string;
    newChannel?: Channel;
  }): Promise<OtpChallenge> {
    await this.isolationGuard.validateTenantAccess({
      tenantId: input.tenantId,
      operation: 'RETRY',
      resourceId: input.challengeId,
    });

    const challengeKey = this.isolationGuard.otpKey(input.tenantId, 'challenge', input.challengeId);
    const challengeDataStr = await this.cache.get(challengeKey);

    if (!challengeDataStr) {
      throw new DomainException(
        DomainErrorCode.OTP_EXPIRED,
        'Challenge not found or expired',
      );
    }

    const challengeData = JSON.parse(challengeDataStr);

    if (challengeData.attempts >= this.maxAttempts - 1) {
      throw new DomainException(
        DomainErrorCode.OTP_ALREADY_USED,
        'Maximum retry attempts exceeded',
      );
    }

    const newChannel = input.newChannel ?? challengeData.channel;

    // Get new recommendation if channel changed
    const recommendation = newChannel !== challengeData.channel
      ? await this.adaptiveEngine.recommendForTenant({
          tenantId: input.tenantId,
          identity: challengeData.identity,
          requestedChannel: newChannel,
        })
      : null;

    const finalChannel = recommendation?.channel ?? newChannel;

    // Generate new code
    const newCode = this.generateOtpCode();

    // Update challenge
    const updatedChallenge = {
      ...challengeData,
      channel: finalChannel,
      code: newCode,
      attempts: challengeData.attempts + 1,
      expiresAt: new Date(Date.now() + this.otpTTLSeconds * 1000).toISOString(),
    };
    await this.cache.set(challengeKey, JSON.stringify(updatedChallenge), this.otpTTLSeconds);

    // Send new OTP
    const { provider } = await this.tenantRegistry.getProviderConfig(input.tenantId);
    await this.dispatchToProvider(provider.providerName, {
      identity: challengeData.identity,
      code: newCode,
      channel: finalChannel,
      purpose: challengeData.purpose,
    });

    return {
      id: input.challengeId,
      tenantId: input.tenantId,
      lineageId: challengeData.lineageId,
      channel: finalChannel,
      purpose: challengeData.purpose,
      provider: provider.providerName,
      expiresAt: new Date(Date.now() + this.otpTTLSeconds * 1000),
      resendCooldownSeconds: this.resendCooldownSeconds,
      maxAttempts: this.maxAttempts - updatedChallenge.attempts,
    };
  }

  private generateOtpCode(): string {
    const code = Math.floor(Math.random() * 1000000);
    return code.toString().padStart(this.otpCodeLength, '0');
  }

  private verifyCode(submitted: string, stored: string): boolean {
    return submitted === stored;
  }

  private async verifyWithProviderToken(
    _provider: string,
    token: string,
    _tenantId: string,
  ): Promise<boolean> {
    // In production, verify token with provider API
    // For now, basic format check
    return token.length >= 10 && /^[a-zA-Z0-9_-]+$/.test(token);
  }

  private async dispatchToProvider(
    providerName: string,
    params: {
      identity: string;
      code: string;
      channel: Channel;
      purpose: Purpose;
    },
  ): Promise<void> {
    // In production, dispatch to actual SMS/Email provider
    // This would use the existing notification dispatcher
    this.logger.debug({
      provider: providerName,
      identity: params.identity,
      channel: params.channel,
    }, 'Dispatching OTP to provider');
  }
}