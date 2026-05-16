import { z } from 'zod';

/**
 * OTP controller DTOs
 * Extracted from inline zod schemas in otp.controller.ts
 *
 * Note: tenantId is validated from x-tenant-id header, not body
 */

// POST /otp/widget/send (body only - tenantId from header)
export const widgetSendDto = z.object({
  identity: z.string().min(1).max(320),
  channel: z.enum(['SMS', 'WHATSAPP', 'VOICE', 'EMAIL']).optional(),
  purpose: z.enum(['IDENTITY_VERIFICATION', 'MFA', 'PASSWORD_RESET']).optional(),
  deviceFingerprint: z.string().max(128).optional(),
  ipAddress: z.string().ip().optional(),
});
export type WidgetSendDto = z.infer<typeof widgetSendDto>;

// POST /otp/widget/verify (body only - tenantId from header)
export const widgetVerifyV2Dto = z.object({
  challengeId: z.string().uuid().optional(),
  providerToken: z.string().min(10).optional(),
  code: z.string().length(6).optional(),
  identity: z.string().min(1).max(320).optional(),
  deviceFingerprint: z.string().max(128).optional(),
  ipAddress: z.string().ip().optional(),
});
export type WidgetVerifyV2Dto = z.infer<typeof widgetVerifyV2Dto>;

// POST /otp/widget/retry (body only - tenantId from header)
export const widgetRetryDto = z.object({
  challengeId: z.string().uuid(),
  newChannel: z.enum(['SMS', 'WHATSAPP', 'VOICE', 'EMAIL']).optional(),
});
export type WidgetRetryDto = z.infer<typeof widgetRetryDto>;