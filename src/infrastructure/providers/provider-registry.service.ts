import { Injectable } from '@nestjs/common';
import { IEmailProvider } from '../../application/ports/driven/i-email-provider.port';
import { ISmsProvider } from '../../application/ports/driven/i-sms-provider.port';
import { MailerooEmailProvider } from './email/maileroo-email.provider';
import { ResendEmailProvider } from './email/resend-email.provider';
import { Msg91SmsProvider } from './sms/msg91-sms.provider';

@Injectable()
export class ProviderRegistryService {
  private readonly smsProviders: ISmsProvider[];
  private readonly emailProviders: IEmailProvider[];

  constructor(
    msg91: Msg91SmsProvider,
    resend: ResendEmailProvider,
    maileroo: MailerooEmailProvider,
  ) {
    this.smsProviders = [msg91];
    this.emailProviders = [resend, maileroo];
  }

  getSmsProvider(providerKey: string): ISmsProvider | undefined {
    return this.smsProviders.find((provider) => provider.providerKey === providerKey);
  }

  getEmailProvider(providerKey: string): IEmailProvider | undefined {
    return this.emailProviders.find((provider) => provider.providerKey === providerKey);
  }

  listProviders(): Array<{ providerKey: string; channel: 'SMS' | 'EMAIL'; enabled: boolean }> {
    return [
      ...this.smsProviders.map((provider) => ({
        providerKey: provider.providerKey,
        channel: provider.channel,
        enabled: provider.isEnabled(),
      })),
      ...this.emailProviders.map((provider) => ({
        providerKey: provider.providerKey,
        channel: provider.channel,
        enabled: provider.isEnabled(),
      })),
    ];
  }
}
