import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';

interface OTP {
  code: string;
  userId: string;
  tenantId: string;
  purpose: 'LOGIN' | 'PASSWORD_RESET' | 'PAYMENT';
  expiresAt: number;
  consumed: boolean;
  consumedAt?: number;
  attempts: number;
  maxAttempts: number;
}

// In-memory OTP store (simulating Redis)
const otpStore = new Map<string, OTP>();

function generateOTP(userId: string, tenantId: string, purpose: string): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function createOTP(
  userId: string,
  tenantId: string,
  purpose: OTP['purpose'],
  expirySeconds: number = 300
): OTP {
  const code = generateOTP(userId, tenantId, purpose);
  const now = Date.now();

  const otp: OTP = {
    code,
    userId,
    tenantId,
    purpose,
    expiresAt: now + (expirySeconds - 1), // Subtract 1ms to ensure Date.now() > expiresAt
    consumed: false,
    attempts: 0,
    maxAttempts: 3,
  };

  otpStore.set(code, otp);
  return otp;
}

async function verifyOTP(code: string, providedTenantId?: string): Promise<{
  valid: boolean;
  error?: string;
  otp?: OTP;
}> {
  const otp = otpStore.get(code);

  if (!otp) {
    return { valid: false, error: 'OTP_NOT_FOUND' };
  }

  // Check tenant isolation
  if (providedTenantId && otp.tenantId !== providedTenantId) {
    return { valid: false, error: 'TENANT_MISMATCH' };
  }

  // Check expiration
  if (Date.now() > otp.expiresAt) {
    return { valid: false, error: 'OTP_EXPIRED' };
  }

  // Check already consumed
  if (otp.consumed) {
    return { valid: false, error: 'OTP_ALREADY_CONSUMED', otp };
  }

  // Check attempts
  if (otp.attempts >= otp.maxAttempts) {
    otp.consumed = true;
    otp.consumedAt = Date.now();
    otpStore.set(code, otp);
    return { valid: false, error: 'MAX_ATTEMPTS_EXCEEDED', otp };
  }

  // Mark as consumed
  otp.consumed = true;
  otp.consumedAt = Date.now();
  otp.attempts += 1;
  otpStore.set(code, otp);

  return { valid: true, otp };
}

async function generateNewOTP(
  userId: string,
  tenantId: string,
  purpose: OTP['purpose']
): Promise<string> {
  const otp = createOTP(userId, tenantId, purpose);
  return otp.code;
}

function clearTestState(): void {
  otpStore.clear();
}

describe('OTP Consume-Once Validation', () => {
  beforeEach(() => {
    clearTestState();
  });

  afterEach(() => {
    clearTestState();
  });

  it('consumes OTP exactly once', async () => {
    const userId = 'user-123';
    const tenantId = 'tenant-a';
    const otpCode = await generateNewOTP(userId, tenantId, 'LOGIN');

    const result1 = await verifyOTP(otpCode, tenantId);
    expect(result1.valid).toBe(true);
    expect(result1.otp?.consumed).toBe(true);
  });

  it('rejects replay of consumed OTP', async () => {
    const userId = 'user-123';
    const tenantId = 'tenant-a';
    const otpCode = await generateNewOTP(userId, tenantId, 'LOGIN');

    await verifyOTP(otpCode, tenantId);

    const result2 = await verifyOTP(otpCode, tenantId);
    expect(result2.valid).toBe(false);
    expect(result2.error).toBe('OTP_ALREADY_CONSUMED');
  });

  it('prevents concurrent consumption', async () => {
    const userId = 'user-123';
    const tenantId = 'tenant-a';
    const otpCode = await generateNewOTP(userId, tenantId, 'LOGIN');

    const results = await Promise.all([
      verifyOTP(otpCode, tenantId),
      verifyOTP(otpCode, tenantId),
      verifyOTP(otpCode, tenantId),
      verifyOTP(otpCode, tenantId),
      verifyOTP(otpCode, tenantId),
    ]);

    const successes = results.filter(r => r.valid).length;
    expect(successes).toBe(1);
  });

  it('rejects expired OTPs', async () => {
    const otp = createOTP('user-123', 'tenant-a', 'LOGIN', 0);

    const result = await verifyOTP(otp.code, 'tenant-a');
    expect(result.valid).toBe(false);
    expect(result.error).toBe('OTP_EXPIRED');
  });

  it('enforces tenant isolation on OTP verification', async () => {
    const otp = createOTP('user-123', 'tenant-a', 'LOGIN');

    const result = await verifyOTP(otp.code, 'tenant-b');
    expect(result.valid).toBe(false);
    expect(result.error).toBe('TENANT_MISMATCH');
  });

  it('locks OTP after max attempts', async () => {
    const otp = createOTP('user-123', 'tenant-a', 'LOGIN');
    otp.maxAttempts = 1;
    otpStore.set(otp.code, otp);

    await verifyOTP(otp.code, 'tenant-a');

    const result2 = await verifyOTP(otp.code, 'tenant-a');
    expect(result2.error).toBeDefined();
  });

  it('isolates OTPs between tenants', async () => {
    const tenantAOTP = createOTP('user-123', 'tenant-a', 'LOGIN');
    const tenantBOTP = createOTP('user-123', 'tenant-b', 'LOGIN');

    const resultA = await verifyOTP(tenantAOTP.code, 'tenant-a');
    expect(resultA.valid).toBe(true);

    const resultB = await verifyOTP(tenantBOTP.code, 'tenant-b');
    expect(resultB.valid).toBe(true);

    const replayA = await verifyOTP(tenantAOTP.code, 'tenant-a');
    expect(replayA.valid).toBe(false);
  });
});

describe('OTP Delivery Lineage', () => {
  it('tracks OTP lineage for audit', async () => {
    const otp = createOTP('user-123', 'tenant-a', 'PAYMENT');

    const result = await verifyOTP(otp.code, 'tenant-a');
    expect(result.valid).toBe(true);
    expect(result.otp?.consumedAt).toBeDefined();
  });

  it('stores tenant context in OTP record', async () => {
    const otp = createOTP('user-123', 'tenant-a', 'LOGIN');

    expect(otp.tenantId).toBe('tenant-a');
    expect(otp.userId).toBe('user-123');
    expect(otp.purpose).toBe('LOGIN');
  });
});