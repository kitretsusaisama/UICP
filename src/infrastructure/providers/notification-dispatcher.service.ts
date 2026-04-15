import { Inject, Injectable, Optional } from '@nestjs/common';
import { IOtpPort, SendOtpParams } from '../../application/ports/driven/i-otp.port';
import { EmailDispatchParams } from '../../application/ports/driven/i-email-provider.port';
import { SmsDispatchParams } from '../../application/ports/driven/i-sms-provider.port';
import { IMetricsPort } from '../../application/ports/driven/i-metrics.port';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { ProviderRoutingService } from '../../application/control-plane/services/provider-routing.service';
import { NotificationTemplateService } from '../otp/notification-template.service';
import { ProviderRegistryService } from './provider-registry.service';

@Injectable()
export class NotificationDispatcherService implements IOtpPort {
  constructor(
    private readonly providerRegistry: ProviderRegistryService,
    private readonly providerRouting: ProviderRoutingService,
    private readonly templates: NotificationTemplateService,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {}

  async send(params: SendOtpParams): Promise<void> {
    const tenantId = params.tenantId;
    const route = await this.providerRouting.resolveRoute(tenantId, params.channel, params.purpose);
    const providerKeys = [route.selectedProviderKey, ...route.fallbackProviderKeys];

    let lastError: Error | undefined;
    for (const providerKey of providerKeys) {
      try {
        if (params.channel === 'SMS') {
          const provider = this.providerRegistry.getSmsProvider(providerKey);
          if (!provider || !provider.isEnabled()) {
            continue;
          }
          const messageParams: SmsDispatchParams = {
            recipient: params.recipient,
            code: params.code,
            purpose: params.purpose,
            tenantName: params.tenantName,
            message: this.buildSmsMessage(params),
          };
          await provider.send(messageParams);
        } else {
          const provider = this.providerRegistry.getEmailProvider(providerKey);
          if (!provider || !provider.isEnabled()) {
            continue;
          }
          const template = this.templates.buildOtpTemplate({
            purpose: params.purpose,
            code: params.code,
            tenantName: params.tenantName,
          });
          const emailParams: EmailDispatchParams = {
            recipient: params.recipient,
            purpose: params.purpose,
            subject: template.subject,
            text: template.text,
            html: template.html,
            tenantName: params.tenantName,
          };
          await provider.send(emailParams);
        }

        this.metrics?.increment('uicp_notification_dispatch_total', {
          tenant_id: tenantId,
          channel: params.channel.toLowerCase(),
          provider: providerKey.toLowerCase(),
          result: 'success',
        });
        return;
      } catch (error) {
        lastError = error as Error;
        this.metrics?.increment('uicp_notification_dispatch_total', {
          tenant_id: tenantId,
          channel: params.channel.toLowerCase(),
          provider: providerKey.toLowerCase(),
          result: 'failed',
        });
      }
    }

    throw Object.assign(
      new Error(`OTP_DELIVERY_FAILED: ${lastError?.message ?? 'No provider available'}`),
      { code: 'OTP_DELIVERY_FAILED' },
    );
  }
  private buildSmsMessage(params: SendOtpParams): string {
    const tenant = params.tenantName ?? 'the platform';
    switch (params.purpose) {
      case 'IDENTITY_VERIFICATION':
        return `Your ${tenant} verification code is ${params.code}.`;
      case 'MFA':
        return `Your ${tenant} login code is ${params.code}.`;
      case 'PASSWORD_RESET':
        return `Your ${tenant} password reset code is ${params.code}.`;
      default:
        return `Your ${tenant} code is ${params.code}.`;
    }
  }
}
