import * as crypto from 'crypto';
import { ApiKeyType, ApiKeyEnv } from '../../domain/entities/api-key.entity';

const PREFIX_MAP: Record<string, { type: ApiKeyType; env: ApiKeyEnv }> = {
  'uF': { type: ApiKeyType.PUBLISHABLE, env: ApiKeyEnv.LIVE },
  'pB': { type: ApiKeyType.PUBLISHABLE, env: ApiKeyEnv.DEV },
  'sF': { type: ApiKeyType.SECRET, env: ApiKeyEnv.LIVE },
  'tB': { type: ApiKeyType.SECRET, env: ApiKeyEnv.DEV },
};

const LIVE_SUFFIX = 'xl';
const HMAC_LENGTH = 44;
const ULID_LENGTH = 26;
const PREFIX_LENGTH = 2;

export interface ParsedApiKey {
  prefix: string;
  type: ApiKeyType;
  env: ApiKeyEnv;
  ulid: string;
  signature?: string;
  isLive: boolean;
}

export function parseApiKey(key: string): ParsedApiKey | null {
  if (!key || key.length < PREFIX_LENGTH + ULID_LENGTH) {
    return null;
  }

  const prefix = key.substring(0, PREFIX_LENGTH);
  const prefixInfo = PREFIX_MAP[prefix];

  if (!prefixInfo) {
    return null;
  }

  const isLive = key.endsWith(LIVE_SUFFIX);
  const hasSignature = prefixInfo.type === ApiKeyType.SECRET;

  let ulid: string;
  let signature: string | undefined;

  if (hasSignature) {
    const keyWithoutPrefix = key.substring(PREFIX_LENGTH);
    ulid = keyWithoutPrefix.substring(0, ULID_LENGTH);

    if (isLive) {
      const withoutSuffix = keyWithoutPrefix.replace(LIVE_SUFFIX, '');
      signature = withoutSuffix.substring(ULID_LENGTH);
    } else {
      signature = keyWithoutPrefix.substring(ULID_LENGTH);
    }
  } else {
    ulid = key.substring(PREFIX_LENGTH, PREFIX_LENGTH + ULID_LENGTH);
  }

  return {
    prefix,
    type: prefixInfo.type,
    env: prefixInfo.env,
    ulid,
    signature,
    isLive,
  };
}

export function generateApiKey(
  type: ApiKeyType,
  env: ApiKeyEnv,
  ulid: string,
  hmacSecret: string,
  tenantId: string
): string {
  const prefixMap: Record<string, string> = {
    [`${ApiKeyType.PUBLISHABLE}_${ApiKeyEnv.LIVE}`]: 'uF',
    [`${ApiKeyType.PUBLISHABLE}_${ApiKeyEnv.DEV}`]: 'pB',
    [`${ApiKeyType.SECRET}_${ApiKeyEnv.LIVE}`]: 'sF',
    [`${ApiKeyType.SECRET}_${ApiKeyEnv.DEV}`]: 'tB',
  };

  const prefix = prefixMap[`${type}_${env}`];

  if (type === ApiKeyType.PUBLISHABLE) {
    return env === ApiKeyEnv.LIVE ? `${prefix}${ulid}${LIVE_SUFFIX}` : `${prefix}${ulid}`;
  }

  const signature = crypto
    .createHmac('sha256', hmacSecret)
    .update(`${ulid}${tenantId}${ulid}`)
    .digest('base64')
    .substring(0, HMAC_LENGTH);

  return env === ApiKeyEnv.LIVE
    ? `${prefix}${ulid}${LIVE_SUFFIX}${signature}`
    : `${prefix}${ulid}${signature}`;
}

export function verifySignature(
  key: string,
  hmacSecret: string,
  tenantId: string
): boolean {
  const parsed = parseApiKey(key);
  if (!parsed || !parsed.signature) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac('sha256', hmacSecret)
    .update(`${parsed.ulid}${tenantId}${parsed.ulid}`)
    .digest('base64')
    .substring(0, HMAC_LENGTH);

  return crypto.timingSafeEqual(
    Buffer.from(parsed.signature),
    Buffer.from(expectedSignature)
  );
}

export function isValidApiKey(key: string): boolean {
  return parseApiKey(key) !== null;
}

export function extractUlidFromKey(key: string): string | null {
  const parsed = parseApiKey(key);
  return parsed?.ulid ?? null;
}

// ============== Webhook Signature Verification ==============

export interface WebhookSignatureOptions {
  signatureHeader: string;
  timestampHeader: string;
  secret: string;
  toleranceSeconds?: number;
}

export interface WebhookVerificationResult {
  isValid: boolean;
  error?: { code: string; message: string };
}

const SIGNATURE_ALGORITHM = 'sha256';
const DEFAULT_TOLERANCE_SECONDS = 300; // 5 minutes

export function verifyWebhookSignature(
  payload: string | Buffer,
  options: WebhookSignatureOptions
): WebhookVerificationResult {
  const { signatureHeader, timestampHeader, secret, toleranceSeconds = DEFAULT_TOLERANCE_SECONDS } = options;

  if (!signatureHeader) {
    return { isValid: false, error: { code: 'MISSING_SIGNATURE', message: 'Missing signature header' } };
  }

  if (!timestampHeader) {
    return { isValid: false, error: { code: 'MISSING_TIMESTAMP', message: 'Missing timestamp header' } };
  }

  const timestamp = parseInt(timestampHeader, 10);
  if (isNaN(timestamp)) {
    return { isValid: false, error: { code: 'INVALID_TIMESTAMP', message: 'Invalid timestamp format' } };
  }

  const now = Math.floor(Date.now() / 1000);
  const age = now - timestamp;
  if (age > toleranceSeconds) {
    return { isValid: false, error: { code: 'SIGNATURE_EXPIRED', message: 'Signature has expired' } };
  }

  if (age < -toleranceSeconds) {
    return { isValid: false, error: { code: 'INVALID_TIMESTAMP', message: 'Timestamp too far in future' } };
  }

  const signature = signatureHeader.replace(/^sha256=/, '');
  const signedPayload = `${timestamp}.${payload}`;
  const expectedSignature = crypto.createHmac(SIGNATURE_ALGORITHM, secret).update(signedPayload).digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
    return { isValid: false, error: { code: 'INVALID_SIGNATURE', message: 'Signature verification failed' } };
  }

  return { isValid: true };
}

export function generateWebhookSignature(payload: string | Buffer, timestamp: number, secret: string): string {
  const signedPayload = `${timestamp}.${payload}`;
  return `sha256=${crypto.createHmac(SIGNATURE_ALGORITHM, secret).update(signedPayload).digest('hex')}`;
}

// ============== Key Utility Functions ==============

export function generateRandomKey(length: number = 32): string {
  return crypto.randomBytes(length).toString('base64url');
}

export function hashSecret(secret: string): string {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

export function verifyHashedSecret(plainSecret: string, hashedSecret: string): boolean {
  const hash = hashSecret(plainSecret);
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(hashedSecret));
}

export function deriveKeyFromSecret(secret: string, salt: string, iterations: number = 100000): Buffer {
  return crypto.pbkdf2Sync(secret, salt, iterations, 32, 'sha256');
}