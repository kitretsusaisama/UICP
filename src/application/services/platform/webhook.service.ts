import { Injectable, Inject, NotFoundException, BadRequestException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { randomBytes, createHmac } from 'crypto';
import { IWebhookRepository, WEBHOOK_REPOSITORY } from '../../../domain/repositories/platform/webhook.repository.interface';
import { IAppRepository, APP_REPOSITORY } from '../../../domain/repositories/platform/app.repository.interface';
import { Webhook } from '../../../domain/entities/platform/webhook.entity';

@Injectable()
export class WebhookService {
  constructor(
    @Inject(WEBHOOK_REPOSITORY) private readonly webhookRepository: IWebhookRepository,
    @Inject(APP_REPOSITORY) private readonly appRepository: IAppRepository,
  ) {}

  async registerWebhook(
    tenantId: string,
    appId: string,
    url: string,
    events: string[]
  ): Promise<Webhook> {

    const app = await this.appRepository.findByIdAndTenant(appId, tenantId);
    if (!app) {
      throw new NotFoundException('App not found');
    }

    // Must be HTTPS for webhooks
    if (!url.startsWith('https://') && process.env.NODE_ENV === 'production') {
      throw new BadRequestException('Webhook URL must use HTTPS');
    }

    const secretKey = `whsec_${randomBytes(24).toString('hex')}`;

    const webhook = new Webhook({
      id: uuidv4(),
      tenantId,
      appId,
      url,
      events,
      secretKey,
      status: 'active',
      failureCount: 0,
    });

    await this.webhookRepository.save(webhook);
    return webhook;
  }

  async listWebhooks(appId: string, tenantId: string): Promise<Webhook[]> {
    return this.webhookRepository.findByAppId(appId, tenantId);
  }

  async getWebhook(id: string, tenantId: string): Promise<Webhook> {
    const webhook = await this.webhookRepository.findByIdAndTenant(id, tenantId);
    if (!webhook) {
      throw new NotFoundException('Webhook not found');
    }
    return webhook;
  }

  async updateWebhook(
    id: string,
    tenantId: string,
    url?: string,
    events?: string[],
    status?: 'active' | 'suspended'
  ): Promise<Webhook> {
    const webhook = await this.getWebhook(id, tenantId);

    const newProps = {
      ...webhook,
      url: url ?? webhook.url,
      events: events ?? webhook.events,
      status: status ?? webhook.status,
    };

    const updatedWebhook = new Webhook(newProps);
    await this.webhookRepository.save(updatedWebhook);
    return updatedWebhook;
  }

  async dispatchEvent(tenantId: string, eventType: string, payload: any): Promise<void> {
    const webhooks = await this.webhookRepository.findByEvent(tenantId, eventType);

    // In a real system, this should queue the events into a background worker (e.g. BullMQ)
    // For MVP we will log the dispatch intent.
    for (const webhook of webhooks) {
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const payloadString = JSON.stringify(payload);

      // Compute HMAC signature: HMAC_SHA256(secret, timestamp + "." + payload)
      const signaturePayload = `${timestamp}.${payloadString}`;
      const signature = createHmac('sha256', webhook.secretKey)
        .update(signaturePayload)
        .digest('hex');

      // This represents the outbound HTTP request
      // We emit this via a logger or queue in the real implementation
      // console.log(`Dispatching ${eventType} to ${webhook.url}`);
      // Headers:
      // uicp-signature: t=${timestamp},v1=${signature}
    }
  }
}
