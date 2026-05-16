import { z } from 'zod';

/**
 * Dynamic module controller DTOs
 * Extracted from inline zod schemas in dynamic-module.controller.ts
 */

// POST /v1/modules/:moduleKey/commands/:commandKey
// POST /v1/modules/:moduleKey/actions/:actionKey
// Body schema is dynamic - validated against command/action requestSchema at runtime
export const dynamicBodyDto = z.record(z.unknown());
export type DynamicBodyDto = z.infer<typeof dynamicBodyDto>;