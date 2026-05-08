import { Webhook } from '../../entities/platform/webhook.entity';

export const WEBHOOK_REPOSITORY = 'WEBHOOK_REPOSITORY';

export interface IWebhookRepository {
  save(webhook: Webhook): Promise<void>;
  findByIdAndTenant(id: string, tenantId: string): Promise<Webhook | null>;
  findByAppId(appId: string, tenantId: string): Promise<Webhook[]>;
  findByEvent(tenantId: string, eventType: string): Promise<Webhook[]>;
}
