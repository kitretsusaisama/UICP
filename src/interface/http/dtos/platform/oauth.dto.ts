import { z } from 'zod';

/**
 * OAuth controller DTOs
 * Extracted from inline zod schemas in oauth.controller.ts
 */

// POST /v1/platform/oauth/token
export const tokenRequestDto = z.object({
  grant_type: z.enum(['authorization_code', 'refresh_token', 'client_credentials']),
  code: z.string().max(500).optional(),
  refresh_token: z.string().max(500).optional(),
  client_id: z.string().min(1).max(100),
  client_secret: z.string().min(1).max(200),
  redirect_uri: z.string().url().optional(),
});
export type TokenRequestDto = z.infer<typeof tokenRequestDto>;