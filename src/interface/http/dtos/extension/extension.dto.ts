import { z } from 'zod';

/**
 * Extension controller DTOs
 */

// POST /v1/extensions/:extensionKey/commands/:commandKey
export const extensionExecuteDto = z.object({
  // Body is passed through to the extension executor
  // No specific schema - extensions define their own payload structure
});
export type ExtensionExecuteDto = z.infer<typeof extensionExecuteDto>;