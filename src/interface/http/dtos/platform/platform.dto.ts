import { z } from 'zod';

/**
 * Platform controller DTOs (discovery, manifest, preview endpoints)
 * Extracted from inline zod schemas in platform.controller.ts
 */

// POST /v1/platform/manifest/preview
export const manifestPreviewDto = z.object({
  moduleKey: z.string().optional(),
  override: z.record(z.unknown()).optional(),
});
export type ManifestPreviewDto = z.infer<typeof manifestPreviewDto>;

// POST /v1/platform/provider-routing/preview
export const providerRoutingPreviewDto = z.object({
  channel: z.enum(['SMS', 'EMAIL']),
  purpose: z.string().min(1).max(100),
});
export type ProviderRoutingPreviewDto = z.infer<typeof providerRoutingPreviewDto>;

// POST /v1/platform/extensions/preview
export const extensionPreviewDto = z.object({
  moduleKey: z.string().min(1),
  extensionPoint: z.string().min(1),
});
export type ExtensionPreviewDto = z.infer<typeof extensionPreviewDto>;