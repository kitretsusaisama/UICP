import { z } from 'zod';

/**
 * Auth controller DTOs
 * Extracted from inline zod schemas in auth.controller.ts
 */

// POST /auth/signup
export const signupDto = z.object({
  identityType: z.enum(['EMAIL', 'PHONE']).optional(),
  email: z.string().min(1).max(320).optional(),
  phone: z.string().min(1).max(32).optional(),
  password: z.string().min(1).max(128),
});
export type SignupDto = z.infer<typeof signupDto>;

// POST /auth/login
export const loginDto = z.object({
  identity: z.string().min(1).max(320),
  identityType: z.enum(['EMAIL', 'PHONE']).optional(),
  password: z.string().min(1).max(128),
  deviceFingerprint: z.string().max(64).optional(),
});
export type LoginDto = z.infer<typeof loginDto>;

// POST /auth/refresh
export const refreshDto = z.object({
  refreshToken: z.string().min(1),
});
export type RefreshDto = z.infer<typeof refreshDto>;

// POST /auth/otp/send
export const otpSendDto = z.object({
  userId: z.string().uuid(),
  purpose: z.enum(['IDENTITY_VERIFICATION', 'MFA', 'PASSWORD_RESET']),
  channel: z.enum(['EMAIL', 'SMS', 'email', 'sms']).optional(),
  recipient: z.string().min(1).max(320).optional(),
  email: z.string().min(1).max(320).optional(),
  phone: z.string().min(1).max(32).optional(),
  tenantName: z.string().max(120).optional(),
});
export type OtpSendDto = z.infer<typeof otpSendDto>;

// POST /auth/otp/verify
export const otpVerifyDto = z.object({
  userId: z.string().uuid(),
  code: z.string().length(6),
  purpose: z.enum(['IDENTITY_VERIFICATION', 'MFA', 'PASSWORD_RESET']),
  identityId: z.string().uuid().optional(),
  sessionId: z.string().uuid().optional(),
});
export type OtpVerifyDto = z.infer<typeof otpVerifyDto>;

// Widget config: GET /auth/otp/widget/config
export const otpWidgetConfigDto = z.object({
  tenantId: z.string().uuid(),
});
export type OtpWidgetConfigDto = z.infer<typeof otpWidgetConfigDto>;

// Widget send: POST /auth/otp/widget/send
export const otpWidgetSendDto = z.object({
  tenantId: z.string().uuid(),
  identity: z.string().min(1).max(320),
  channel: z.enum(['SMS', 'WHATSAPP', 'VOICE', 'EMAIL']).optional(),
  purpose: z.enum(['IDENTITY_VERIFICATION', 'MFA', 'PASSWORD_RESET']).optional(),
  deviceFingerprint: z.string().max(128).optional(),
});
export type OtpWidgetSendDto = z.infer<typeof otpWidgetSendDto>;

// Widget verify: POST /auth/otp/widget/verify
export const otpWidgetVerifyDto = z.object({
  tenantId: z.string().uuid(),
  challengeId: z.string().uuid().optional(),
  providerToken: z.string().min(10).optional(),
  code: z.string().length(6).optional(),
  identity: z.string().min(1).max(320).optional(),
  deviceFingerprint: z.string().max(128).optional(),
  ipAddress: z.string().ip().optional(),
});
export type OtpWidgetVerifyDto = z.infer<typeof otpWidgetVerifyDto>;

// POST /auth/password/change
export const changePasswordDto = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: z.string().min(1).max(128),
});
export type ChangePasswordDto = z.infer<typeof changePasswordDto>;

// POST /auth/oauth2/introspect
export const introspectDto = z.object({
  token: z.string().min(1),
});
export type IntrospectDto = z.infer<typeof introspectDto>;

// POST /auth/password/reset/request
export const passwordResetRequestDto = z.object({
  identity: z.string().min(1).max(320),
  identityType: z.enum(['EMAIL', 'PHONE']).optional(),
});
export type PasswordResetRequestDto = z.infer<typeof passwordResetRequestDto>;

// POST /auth/password/reset/confirm
export const passwordResetConfirmDto = z.object({
  resetToken: z.string().min(1),
  newPassword: z.string().min(1).max(128),
});
export type PasswordResetConfirmDto = z.infer<typeof passwordResetConfirmDto>;

// POST /auth/actor/switch
export const switchActorDto = z.object({
  actorId: z.string().uuid(),
});
export type SwitchActorDto = z.infer<typeof switchActorDto>;