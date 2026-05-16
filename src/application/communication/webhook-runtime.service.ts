import { Injectable } from '@nestjs/common';
import { ProviderWebhookEvent } from './communication.types';

@Injectable()
export class WebhookRuntime {
  private readonly processed = new Set<string>();

  process(provider: string, payload: unknown, headers: Record<string, string>): ProviderWebhookEvent & { duplicate: boolean } {
    const eventId = headers['svix-id'] ?? headers['x-event-id'] ?? `${provider}:${JSON.stringify(payload).length}`;
    const key = `${provider}:${eventId}`;
    const duplicate = this.processed.has(key);
    if (!duplicate) {
      this.processed.add(key);
    }

    return {
      providerName: provider.toUpperCase(),
      eventId,
      eventType: headers['x-event-type'] ?? 'provider.event',
      payload,
      duplicate,
    };
  }
}
