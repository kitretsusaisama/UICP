import { Inject, Injectable, Logger } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { ITenantOtpAdaptiveModelRepository } from '../../../application/ports/driven/i-otp-adaptive-model.port';
import { TenantIsolationGuard } from '../isolation/tenant-isolation-guard';
import { TenantProviderRegistry } from '../registry/tenant-provider-registry';

export type Channel = 'SMS' | 'WHATSAPP' | 'VOICE' | 'EMAIL';

export interface DeliveryRecommendation {
  tenantId: string;
  providerKey: string;
  channel: Channel;
  confidence: number;
  fallbackChannels: Channel[];
  estimatedLatencyMs: number;
  reason: string;
}

@Injectable()
export class TenantAdaptiveEngine {
  private readonly logger = new Logger(TenantAdaptiveEngine.name);
  private readonly defaultChannelRates: Record<Channel, number> = {
    SMS: 0.85,
    WHATSAPP: 0.95,
    VOICE: 0.75,
    EMAIL: 0.90,
  };

  constructor(
    private readonly isolationGuard: TenantIsolationGuard,
    private readonly tenantRegistry: TenantProviderRegistry,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
    @Inject(INJECTION_TOKENS.OTP_ADAPTIVE_MODEL_REPO)
    private readonly adaptiveModelRepo: ITenantOtpAdaptiveModelRepository,
  ) {}

  async getModel(tenantId: string): Promise<Record<string, number>> {
    await this.isolationGuard.validateTenantAccess({
      tenantId,
      operation: 'SEND',
    });

    const cacheKey = this.isolationGuard.adaptiveModelKey(tenantId);
    const cached = await this.cache.get(cacheKey);

    if (cached) {
      return JSON.parse(cached);
    }

    const model = await this.adaptiveModelRepo.findByTenantId(tenantId);
    const rates = model?.channelSuccessRates ?? this.defaultChannelRates;

    await this.cache.set(cacheKey, JSON.stringify(rates), 3600);
    return rates;
  }

  async recommendForTenant(input: {
    tenantId: string;
    identity: string;
    requestedChannel: Channel;
    timeOfDay?: number;
  }): Promise<DeliveryRecommendation> {
    const timeOfDay = input.timeOfDay ?? new Date().getHours();

    const model = await this.getModel(input.tenantId);

    const primaryProvider = await this.tenantRegistry.getPrimaryProvider(input.tenantId);
    const circuitState = await this.tenantRegistry.getCircuitState(
      input.tenantId,
      primaryProvider.providerName,
    );

    const rateLimit = await this.tenantRegistry.checkRateLimit(
      input.tenantId,
      primaryProvider.providerName,
    );

    if (!rateLimit.allowed || circuitState.state === 'OPEN') {
      const fallback = await this.tenantRegistry.getFallbackChain(input.tenantId);
      const fallbackChannel = this.getFallbackChannel(input.requestedChannel);
      const firstFallback = fallback[0];

      return {
        tenantId: input.tenantId,
        providerKey: firstFallback ? firstFallback.providerName : primaryProvider.providerName,
        channel: fallbackChannel,
        confidence: 0.5,
        fallbackChannels: this.getAlternativeChannels(input.requestedChannel),
        estimatedLatencyMs: 3000,
        reason: !rateLimit.allowed
          ? 'Rate limit exceeded, using fallback channel'
          : 'Primary provider circuit open, using fallback',
      };
    }

    const recommendedChannel = this.selectBestChannel(model, input.requestedChannel, timeOfDay);
    const confidence = model[recommendedChannel] ?? 0.8;

    return {
      tenantId: input.tenantId,
      providerKey: primaryProvider.providerName,
      channel: recommendedChannel,
      confidence,
      fallbackChannels: this.getAlternativeChannels(recommendedChannel),
      estimatedLatencyMs: recommendedChannel === 'WHATSAPP' ? 1500 : 2500,
      reason: `Channel ${recommendedChannel} selected with ${(confidence * 100).toFixed(1)}% success rate`,
    };
  }

  async recordTenantOutcome(params: {
    tenantId: string;
    identity: string;
    channel: Channel;
    providerKey: string;
    success: boolean;
    latencyMs: number;
  }): Promise<void> {
    const model = await this.adaptiveModelRepo.findByTenantId(params.tenantId);

    const currentRates = model?.channelSuccessRates ?? { ...this.defaultChannelRates };
    const currentProviderRates = model?.providerSuccessRates ?? {};

    const alpha = 0.2;
    const newChannelRate = (currentRates[params.channel] ?? 0.8) * (1 - alpha) + (params.success ? 1 : 0) * alpha;
    const newProviderRate = (currentProviderRates[params.providerKey] ?? 0.8) * (1 - alpha) + (params.success ? 1 : 0) * alpha;

    const updatedRates = {
      ...currentRates,
      [params.channel]: newChannelRate,
    };

    const updatedProviderRates = {
      ...currentProviderRates,
      [params.providerKey]: newProviderRate,
    };

    await this.adaptiveModelRepo.upsert(params.tenantId, {
      channelSuccessRates: updatedRates,
      providerSuccessRates: updatedProviderRates,
      trainingDataPoints: (model?.trainingDataPoints ?? 0) + 1,
    });

    const cacheKey = this.isolationGuard.adaptiveModelKey(params.tenantId);
    await this.cache.set(cacheKey, JSON.stringify(updatedRates), 3600);

    this.logger.debug({
      tenantId: params.tenantId,
      channel: params.channel,
      success: params.success,
      newRate: newChannelRate,
    }, 'Adaptive model updated');
  }

  private selectBestChannel(
    rates: Record<string, number>,
    requested: Channel,
    hour: number,
  ): Channel {
    const availableChannels: Channel[] = ['SMS', 'WHATSAPP', 'VOICE', 'EMAIL'];
    let bestChannel = requested;
    let bestRate = rates[requested] ?? 0.8;

    for (const channel of availableChannels) {
      const rate = rates[channel] ?? 0.8;
      if (rate > bestRate) {
        bestRate = rate;
        bestChannel = channel;
      }
    }

    return bestChannel;
  }

  private getFallbackChannel(channel: Channel): Channel {
    const fallbacks: Record<Channel, Channel> = {
      SMS: 'WHATSAPP',
      WHATSAPP: 'SMS',
      VOICE: 'SMS',
      EMAIL: 'SMS',
    };
    return fallbacks[channel] ?? 'SMS';
  }

  private getAlternativeChannels(channel: Channel): Channel[] {
    const alternatives: Record<Channel, Channel[]> = {
      SMS: ['WHATSAPP', 'VOICE', 'EMAIL'],
      WHATSAPP: ['SMS', 'VOICE', 'EMAIL'],
      VOICE: ['SMS', 'WHATSAPP', 'EMAIL'],
      EMAIL: ['SMS', 'WHATSAPP', 'VOICE'],
    };
    return alternatives[channel] ?? ['SMS'];
  }
}