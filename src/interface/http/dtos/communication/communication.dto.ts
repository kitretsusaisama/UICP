import { z } from 'zod';

/**
 * Communication controller DTOs
 * Extracted from inline zod schemas in communication.controller.ts
 */

export const purposeSchema = z.enum([
  'LOGIN_OTP',
  'SIGNUP_OTP',
  'MFA',
  'PASSWORD_RESET',
  'VERIFY_EMAIL',
  'TENANT_INVITE',
  'SECURITY_ALERT',
]);

export const channelSchema = z.enum(['SMS', 'EMAIL', 'WHATSAPP', 'VOICE']);

// POST /v1/auth/otp/runtime/send
export const sendOtpDto = z.object({
  userId: z.string().uuid(),
  recipient: z.string().min(1).max(320),
  channel: channelSchema.default('SMS'),
  purpose: purposeSchema.default('LOGIN_OTP'),
  tenantName: z.string().max(120).optional(),
});
export type SendOtpDto = z.infer<typeof sendOtpDto>;

// POST /v1/auth/otp/retry
export const retryOtpDto = sendOtpDto.extend({
  challengeId: z.string().uuid(),
});
export type RetryOtpDto = z.infer<typeof retryOtpDto>;

// POST /v1/auth/otp/runtime/verify
export const verifyOtpDto = z.object({
  userId: z.string().uuid(),
  code: z.string().length(6),
  purpose: purposeSchema.default('LOGIN_OTP'),
  challengeId: z.string().uuid().optional(),
});
export type VerifyOtpDto = z.infer<typeof verifyOtpDto>;

// POST /v1/auth/otp/widget/verify-token
export const commWidgetVerifyDto = z.object({
  provider: z.literal('MSG91').default('MSG91'),
  accessToken: z.string().min(1),
  challengeId: z.string().uuid().optional(),
});
export type CommWidgetVerifyDto = z.infer<typeof commWidgetVerifyDto>;

// POST /v1/communication/email/send
export const sendEmailDto = z.object({
  recipient: z.string().email(),
  subject: z.string().min(1).max(200),
  text: z.string().optional(),
  html: z.string().optional(),
  purpose: purposeSchema.optional(),
  tenantName: z.string().max(120).optional(),
  idempotencyKey: z.string().max(200).optional(),
});
export type SendEmailDto = z.infer<typeof sendEmailDto>;

// POST /v1/communication/email/batch
export const sendEmailBatchDto = z.object({
  items: z.array(sendEmailDto).min(1).max(100),
});
export type SendEmailBatchDto = z.infer<typeof sendEmailBatchDto>;

// POST /v1/communication/templates
export const createTemplateDto = z.object({
  name: z.string().min(1).max(100),
  subject: z.string().min(1).max(200).optional(),
  body: z.string().min(1).max(10000),
  bodyType: z.enum(['text', 'html']).default('text'),
  variables: z.array(z.string()).optional(),
});
export type CreateTemplateDto = z.infer<typeof createTemplateDto>;

// POST /v1/communication/webhooks/:provider
export const webhookPayloadDto = z.record(z.unknown());
export type WebhookPayloadDto = z.infer<typeof webhookPayloadDto>;