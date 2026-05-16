import { z } from 'zod';

/**
 * App controller DTOs
 * Extracted from inline zod schemas in app.controller.ts
 */

// POST /v1/platform/apps
export const createAppDto = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  metadata: z.record(z.unknown()).optional(),
});
export type CreateAppDto = z.infer<typeof createAppDto>;