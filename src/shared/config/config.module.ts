import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { z } from 'zod';

/**
 * Zod schema for all required environment variables.
 * The application will refuse to start if any required variable is missing
 * or fails validation.
 */
const envSchema = z.object({
  // ── Application ──────────────────────────────────────────────────────
  NODE_ENV: z
    .enum(['development', 'test', 'production'])
    .default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),

  // ── MySQL (Primary) ───────────────────────────────────────────────────
  DB_HOST: z.string().min(1),
  DB_PORT: z.coerce.number().int().min(1).max(65535).default(3306),
  DB_NAME: z.string().min(1),
  DB_USER: z.string().min(1),
  DB_PASSWORD: z.string().min(1),
  DB_POOL_MIN: z.coerce.number().int().min(1).default(5),
  DB_POOL_MAX: z.coerce.number().int().min(1).default(20),

  // ── Redis ─────────────────────────────────────────────────────────────
  REDIS_HOST: z.string().min(1),
  REDIS_PORT: z.coerce.number().int().min(1).max(65535).default(6379),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_TLS: z
    .string()
    .transform((v) => v === 'true')
    .default('false'),

  // ── JWT (RS256) ───────────────────────────────────────────────────────
  JWT_PRIVATE_KEY: z.string().optional(),              // Raw PEM (local dev / CI)
  JWT_PRIVATE_KEY_ENC: z.string().optional(),          // AES-256-GCM encrypted PEM (production)
  JWT_PUBLIC_KEY: z.string().min(1), // PEM-encoded RSA public key
  JWT_KID: z.string().min(1), // Current key ID
  JWT_ISSUER: z.string().url(),
  JWT_AUDIENCE: z.string().min(1),
  JWT_ACCESS_TOKEN_TTL_S: z.coerce.number().int().min(60).default(900), // 15 min
  JWT_REFRESH_TOKEN_TTL_S: z.coerce.number().int().min(3600).default(604800), // 7 days

  // ── Encryption (AES-256-GCM) ──────────────────────────────────────────
  ENCRYPTION_MASTER_KEY: z
    .string()
    .length(64)
    .regex(/^[0-9a-fA-F]+$/, 'Must be a 64-char hex string (32 bytes)'),
  ENCRYPTION_MASTER_KEY_ID: z.string().min(1),
  // Optional deprecated key for rotation support
  ENCRYPTION_DEPRECATED_KEY: z.string().length(64).optional(),
  ENCRYPTION_DEPRECATED_KEY_ID: z.string().optional(),

  // ── Credential Hashing ────────────────────────────────────────────────
  BCRYPT_ROUNDS: z.coerce.number().int().min(10).max(14).default(12),
  PASSWORD_PEPPER: z.string().min(32),

  // ── OTP ───────────────────────────────────────────────────────────────
  OTP_TTL_S: z.coerce.number().int().min(60).default(300), // 5 min
  // Firebase (SMS)
  FIREBASE_PROJECT_ID: z.string().optional(),
  FIREBASE_CLIENT_EMAIL: z.string().email().optional(),
  FIREBASE_PRIVATE_KEY: z.string().optional(),
  // SMTP (email)
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().int().optional(),
  SMTP_SECURE: z.string().optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_FROM: z.string().email().optional(),
  MAIL_BRAND_NAME: z.string().optional(),
  MAIL_LOGO_URL: z.string().url().optional(),
  MAIL_SUPPORT_EMAIL: z.string().email().optional(),
  MAIL_ACCENT_COLOR: z.string().optional(),
  MAIL_FOOTER_TEXT: z.string().optional(),
  PLATFORM_BASE_DOMAIN: z.string().optional(),
  MSG91_ENABLED: z.string().optional(),
  MSG91_AUTH_KEY: z.string().optional(),
  MSG91_SENDER_ID: z.string().optional(),
  MSG91_ROUTE: z.string().optional(),
  MSG91_COUNTRY: z.string().optional(),
  MSG91_TEMPLATE_ID_IDENTITY_VERIFICATION: z.string().optional(),
  MSG91_TEMPLATE_ID_MFA: z.string().optional(),
  MSG91_TEMPLATE_ID_PASSWORD_RESET: z.string().optional(),
  RESEND_ENABLED: z.string().optional(),
  RESEND_API_KEY: z.string().optional(),
  RESEND_FROM: z.string().email().optional(),
  MAILEROO_ENABLED: z.string().optional(),
  MAILEROO_API_KEY: z.string().optional(),
  MAILEROO_FROM: z.string().email().optional(),
});

export type AppConfig = z.infer<typeof envSchema>;

function validate(config: Record<string, unknown>): AppConfig {
  const result = envSchema.safeParse(config);
  if (!result.success) {
    const formatted = result.error.issues
      .map((issue) => `  ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Environment validation failed:\n${formatted}`);
  }
  return result.data;
}

@Module({
  imports: [
    NestConfigModule.forRoot({
      isGlobal: true,
      validate,
      expandVariables: true,
    }),
  ],
  exports: [NestConfigModule],
})
export class ConfigModule {}
