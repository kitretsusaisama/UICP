import { z } from 'zod';

/**
 * Webhook controller DTOs
 * Extracted from inline zod schemas in webhook.controller.ts
 */

// POST /v1/platform/webhooks
export const createWebhookDto = z.object({
  name: z.string().min(1).max(100),
  url: z.string().url(),
  events: z.array(z.string()).min(1),
  secret: z.string().max(500).optional(),
  active: z.boolean().default(true),
});
export type CreateWebhookDto = z.infer<typeof createWebhookDto>;