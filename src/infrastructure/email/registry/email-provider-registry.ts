import { Injectable, Logger } from '@nestjs/common';
import { IEmailProviderAdapter } from '../../../application/ports/driven/i-email-provider.port';
import { ResendEmailAdapter } from '../adapters/resend/resend.adapter';
import { MailerooEmailAdapter } from '../adapters/maileroo/maileroo.adapter';
import { SmtpEmailAdapter } from '../adapters/smtp/smtp.adapter';

@Injectable()
export class EmailProviderRegistry {
  private readonly logger = new Logger(EmailProviderRegistry.name);
  private readonly adapters = new Map<string, IEmailProviderAdapter>();

  constructor(
    private readonly resend: ResendEmailAdapter,
    private readonly maileroo: MailerooEmailAdapter,
    private readonly smtp: SmtpEmailAdapter,
  ) {
    this.registerAdapter(resend);
    this.registerAdapter(maileroo);
    this.registerAdapter(smtp);

    this.logger.log(
      { providers: Array.from(this.adapters.keys()) },
      'Email provider registry initialized',
    );
  }

  private registerAdapter(adapter: IEmailProviderAdapter): void {
    this.adapters.set(adapter.providerKey, adapter);
    this.logger.debug({ provider: adapter.providerKey }, 'Registered email adapter');
  }

  getAdapter(providerKey: string): IEmailProviderAdapter | undefined {
    return this.adapters.get(providerKey.toUpperCase());
  }

  getAllAdapters(): IEmailProviderAdapter[] {
    return Array.from(this.adapters.values());
  }

  listProviders(): Array<{ providerKey: string; providerType: string; enabled: boolean }> {
    return Array.from(this.adapters.values()).map((adapter) => ({
      providerKey: adapter.providerKey,
      providerType: adapter.providerType,
      enabled: true,
    }));
  }

  isProviderAvailable(providerKey: string): boolean {
    return this.adapters.has(providerKey.toUpperCase());
  }
}