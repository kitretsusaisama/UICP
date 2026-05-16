import { z } from 'zod';

/**
 * AppSecret controller DTOs
 * Extracted from inline zod schemas in app-secret.controller.ts
 */

// POST /v1/platform/apps/:appId/secrets
export const createSecretDto = z.object({
  name: z.string().min(1).max(100),
  value: z.string().min(1).max(10000),
  expiresAt: z.string().datetime().optional(),
});
export type CreateSecretDto = z.infer<typeof createSecretDto>;