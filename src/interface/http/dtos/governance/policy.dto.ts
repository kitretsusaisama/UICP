import { z } from 'zod';

/**
 * Policy controller DTOs
 * Extracted from inline zod schemas in policy.controller.ts
 */

// POST /v1/policies
export const createPolicyDto = z.object({
  name: z.string().min(1).max(100),
  rules: z.unknown(), // PolicyRules - validating as unknown for flexibility
  description: z.string().max(500).optional(),
});
export type CreatePolicyDto = z.infer<typeof createPolicyDto>;

// POST /v1/policies/:id/test
export const testPolicyDto = z.object({
  context: z.record(z.unknown()),
});
export type TestPolicyDto = z.infer<typeof testPolicyDto>;