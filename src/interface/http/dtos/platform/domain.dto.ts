import { z } from 'zod';

/**
 * Domain controller DTOs
 * Extracted from inline zod schemas in domain.controller.ts
 */

// POST /v1/platform/domains
export const createDomainDto = z.object({
  domain: z.string().min(1).max(253).regex(/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/),
  tenantId: z.string().uuid().optional(),
  verified: z.boolean().default(false),
});
export type CreateDomainDto = z.infer<typeof createDomainDto>;