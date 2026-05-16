import { z } from 'zod';

/**
 * Role controller DTOs
 * Extracted from inline zod schemas in role.controller.ts
 */

// POST /v1/roles
export const createRoleDto = z.object({
  name: z.string().min(1).max(100),
  permissions: z.array(z.string()).min(1),
  description: z.string().max(500).optional(),
});
export type CreateRoleDto = z.infer<typeof createRoleDto>;

// POST /v1/roles/assign
export const assignRoleDto = z.object({
  userId: z.string().uuid(),
  roleId: z.string().uuid(),
  expiresAt: z.string().datetime().optional(),
});
export type AssignRoleDto = z.infer<typeof assignRoleDto>;