import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { ProviderRoutingService } from '../control-plane/services/provider-routing.service';
import {
  CommunicationChannel,
  CommunicationPurpose,
  ProviderResolution,
} from './communication.types';

function toOtpPurpose(purpose: CommunicationPurpose): 'IDENTITY_VERIFICATION' | 'MFA' | 'PASSWORD_RESET' {
  if (purpose === 'PASSWORD_RESET') return 'PASSWORD_RESET';
  if (purpose === 'MFA' || purpose === 'SECURITY_ALERT') return 'MFA';
  return 'IDENTITY_VERIFICATION';
}

@Injectable()
export class TenantProviderResolver {
  constructor(private readonly routing: ProviderRoutingService) {}

  async resolve(input: {
    tenantId: string;
    channel: CommunicationChannel;
    purpose: CommunicationPurpose;
    tenantName?: string;
  }): Promise<ProviderResolution> {
    const route = await this.routing.resolveRoute(
      input.tenantId,
      input.channel === 'EMAIL' ? 'EMAIL' : 'SMS',
      toOtpPurpose(input.purpose),
    );

    const primaryName = route.selectedProviderKey;
    const fallbackNames = route.fallbackProviderKeys;
    const lineageId = randomUUID();

    return {
      tenantId: input.tenantId,
      channel: input.channel,
      purpose: input.purpose,
      lineageId,
      primary: {
        providerName: primaryName,
        providerType: primaryName.toLowerCase(),
        priority: 1,
        circuitState: 'CLOSED',
      },
      fallbacks: fallbackNames.map((providerName, index) => ({
        providerName,
        providerType: providerName.toLowerCase(),
        priority: index + 2,
        circuitState: 'CLOSED' as const,
      })),
      template: {
        templateKey: input.purpose.toLowerCase(),
        locale: 'en',
        version: 1,
      },
      sender: {},
      branding: {
        displayName: input.tenantName ?? 'UICP',
      },
      policy: {
        resendCooldownSeconds: 30,
        maxRetries: 3,
        retryChannels: input.channel === 'EMAIL' ? ['EMAIL'] : ['SMS', 'WHATSAPP', 'VOICE', 'EMAIL'],
        rateLimitPerMinute: 60,
        dailyLimit: input.channel === 'SMS' ? 1000 : 10000,
      },
    };
  }
}
