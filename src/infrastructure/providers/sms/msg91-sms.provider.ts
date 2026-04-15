import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ISmsProvider, SmsDispatchParams } from '../../../application/ports/driven/i-sms-provider.port';

@Injectable()
export class Msg91SmsProvider implements ISmsProvider {
  readonly providerKey = 'MSG91';
  readonly channel = 'SMS' as const;

  constructor(private readonly config: ConfigService) {}

  isEnabled(): boolean {
    return this.config.get<string>('MSG91_ENABLED', 'true') !== 'false';
  }

  async send(params: SmsDispatchParams): Promise<{ providerMessageId?: string }> {
    if (!this.isEnabled()) {
      return { providerMessageId: 'msg91-disabled' };
    }

    const authKey = this.config.get<string>('MSG91_AUTH_KEY');
    const sender = this.config.get<string>('MSG91_SENDER_ID');
    if (!authKey || !sender) {
      throw new Error('MSG91 configuration missing');
    }

    const body = {
      template_id: this.templateIdForPurpose(params.purpose),
      recipients: [
        {
          mobiles: params.recipient.replace(/^\+/, ''),
          otp: params.code,
        },
      ],
      sender,
      route: this.config.get<string>('MSG91_ROUTE', '4'),
    };

    const response = await fetch('https://control.msg91.com/api/v5/flow/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        authkey: authKey,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`MSG91 dispatch failed with status ${response.status}`);
    }

    const payload = (await response.json()) as { request_id?: string };
    return { providerMessageId: payload.request_id };
  }

  private templateIdForPurpose(purpose: SmsDispatchParams['purpose']): string | undefined {
    switch (purpose) {
      case 'IDENTITY_VERIFICATION':
        return this.config.get<string>('MSG91_TEMPLATE_ID_IDENTITY_VERIFICATION');
      case 'MFA':
        return this.config.get<string>('MSG91_TEMPLATE_ID_MFA');
      case 'PASSWORD_RESET':
        return this.config.get<string>('MSG91_TEMPLATE_ID_PASSWORD_RESET');
      default:
        return undefined;
    }
  }
}
