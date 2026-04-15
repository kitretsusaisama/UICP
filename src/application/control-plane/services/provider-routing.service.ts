import { Inject, Injectable, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IMetricsPort } from '../../ports/driven/i-metrics.port';
import { IProviderRoutingRepository } from '../../ports/driven/i-provider-routing.repository';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { OtpChannel, OtpPurpose } from '../../ports/driven/i-otp.port';

export interface ProviderRouteDecision {
  selectedProviderKey: string;
  fallbackProviderKeys: string[];
  strategy: 'default' | 'tenant_override';
}

@Injectable()
export class ProviderRoutingService {
  constructor(
    @Inject(INJECTION_TOKENS.PROVIDER_ROUTING_REPOSITORY)
    private readonly providerRoutingRepository: IProviderRoutingRepository,
    private readonly config: ConfigService,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {}

  async resolveRoute(
    tenantId: string,
    channel: OtpChannel,
    purpose: OtpPurpose,
  ): Promise<ProviderRouteDecision> {
    const rules = await this.providerRoutingRepository.listRules(tenantId);
    const applicable = rules
      .filter((rule) => rule.enabled && rule.channel === channel && rule.purpose === purpose)
      .sort((a, b) => a.priority - b.priority);

    if (applicable.length > 0) {
      const [selected, ...fallback] = applicable;
      this.metrics?.increment('uicp_provider_route_total', {
        tenant_id: tenantId,
        channel: channel.toLowerCase(),
        strategy: 'tenant_override',
      });
      return {
        selectedProviderKey: selected!.providerKey,
        fallbackProviderKeys: fallback.filter((rule) => rule.fallbackOnError).map((rule) => rule.providerKey),
        strategy: 'tenant_override',
      };
    }

    const defaultSms = this.config.get<string>('MSG91_ENABLED', 'true') !== 'false' ? ['MSG91'] : [];
    const defaultEmail = ['RESEND', 'MAILEROO'];
    const defaultRoute = channel === 'SMS' ? defaultSms : defaultEmail;
    const [selectedProviderKey, ...fallbackProviderKeys] = defaultRoute;

    this.metrics?.increment('uicp_provider_route_total', {
      tenant_id: tenantId,
      channel: channel.toLowerCase(),
      strategy: 'default',
    });

    return {
      selectedProviderKey: selectedProviderKey ?? (channel === 'SMS' ? 'MSG91' : 'RESEND'),
      fallbackProviderKeys,
      strategy: 'default',
    };
  }
}
