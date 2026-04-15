import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EmailDispatchParams, IEmailProvider } from '../../../application/ports/driven/i-email-provider.port';

@Injectable()
export class ResendEmailProvider implements IEmailProvider {
  readonly providerKey = 'RESEND';
  readonly channel = 'EMAIL' as const;

  constructor(private readonly config: ConfigService) {}

  isEnabled(): boolean {
    return this.config.get<string>('RESEND_ENABLED', 'true') !== 'false';
  }

  async send(params: EmailDispatchParams): Promise<{ providerMessageId?: string }> {
    if (!this.isEnabled()) {
      throw new Error('RESEND provider is disabled');
    }

    const apiKey = this.config.get<string>('RESEND_API_KEY');
    const from = this.config.get<string>('RESEND_FROM') ?? this.config.get<string>('SMTP_FROM');
    if (!apiKey || !from) {
      throw new Error('Resend configuration missing');
    }

    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from,
        to: [params.recipient],
        subject: params.subject,
        text: params.text,
        html: params.html,
      }),
    });

    if (!response.ok) {
      throw new Error(`Resend dispatch failed with status ${response.status}`);
    }

    const payload = (await response.json()) as { id?: string };
    return { providerMessageId: payload.id };
  }
}
