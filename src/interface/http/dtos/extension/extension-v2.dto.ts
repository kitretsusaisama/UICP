import { z } from 'zod';

/**
 * Extension controller DTOs
 * Extracted from inline zod schemas in extension.controller.ts
 */

// POST /v1/extensions/:extensionKey/commands/:commandKey
export const extensionCommandDto = z.record(z.unknown());
export type ExtensionCommandDto = z.infer<typeof extensionCommandDto>;