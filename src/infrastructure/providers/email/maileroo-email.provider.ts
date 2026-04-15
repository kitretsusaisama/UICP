import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EmailDispatchParams, IEmailProvider } from '../../../application/ports/driven/i-email-provider.port';

@Injectable()
export class MailerooEmailProvider implements IEmailProvider {
  readonly providerKey = 'MAILEROO';
  readonly channel = 'EMAIL' as const;

  constructor(private readonly config: ConfigService) {}

  isEnabled(): boolean {
    return this.config.get<string>('MAILEROO_ENABLED', 'true') !== 'false';
  }

  async send(params: EmailDispatchParams): Promise<{ providerMessageId?: string }> {
    if (!this.isEnabled()) {
      throw new Error('MAILEROO provider is disabled');
    }

    const apiKey = this.config.get<string>('MAILEROO_API_KEY');
    const fromAddress = this.config.get<string>('MAILEROO_FROM') ?? this.config.get<string>('SMTP_FROM');
    if (!apiKey || !fromAddress) {
      throw new Error('Maileroo configuration missing');
    }

    const response = await fetch('https://smtp.maileroo.com/api/v2/emails', {
      method: 'POST',
      headers: {
        'X-API-Key': apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: {
          address: fromAddress,
        },
        to: [{ address: params.recipient }],
        subject: params.subject,
        html: params.html,
        plain: params.text,
        tags: {
          purpose: params.purpose,
        },
      }),
    });

    if (!response.ok) {
      throw new Error(`Maileroo dispatch failed with status ${response.status}`);
    }

    const payload = (await response.json()) as { data?: { id?: string }; id?: string };
    return { providerMessageId: payload.data?.id ?? payload.id };
  }
}
