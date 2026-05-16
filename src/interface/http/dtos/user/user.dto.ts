import { z } from 'zod';

/**
 * User controller DTOs
 * Extracted from inline zod schemas in user.controller.ts
 */

// PATCH /user
export const patchUserDto = z.object({
  displayName: z.string().min(1).max(200).optional(),
  metadata: z.record(z.unknown()).optional(),
});
export type PatchUserDto = z.infer<typeof patchUserDto>;

// POST /user/identities
export const addIdentityDto = z.object({
  type: z.enum(['email', 'phone']),
  value: z.string().min(1).max(320),
});
export type AddIdentityDto = z.infer<typeof addIdentityDto>;