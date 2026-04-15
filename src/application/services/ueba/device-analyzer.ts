import { Injectable, Logger } from '@nestjs/common';
import { createHash } from 'crypto';
import { ICachePort } from '../../ports/driven/i-cache.port';

export interface DeviceSignals {
  userAgent: string;
  acceptLanguage?: string;
  screenResolution?: string;
  timezone?: string;
  platform?: string;
}

/**
 * Analyzes device trust for login attempts.
 *
 * Fingerprint: SHA-256(ua:lang:screen:tz:platform).slice(0,16) → 32-char hex string
 *
 * Scoring (Section 10.1):
 *   - Known device (in SMEMBERS devices:{tenantId}:{userId}): 0.0
 *   - Unknown device, user has ≥1 known device:               0.5
 *   - Unknown device, user has 0 known devices (new user):    0.1
 *
 * Implements: Req 11.5
 */
@Injectable()
export class DeviceAnalyzer {
  private readonly logger = new Logger(DeviceAnalyzer.name);

  constructor(private readonly cache: ICachePort) {}

  /**
   * Computes the device anomaly score.
   * Returns the fingerprint alongside the score for downstream use (e.g. session tagging).
   */
  async score(
    signals: DeviceSignals,
    tenantId: string,
    userId: string,
  ): Promise<{ score: number; fingerprint: string }> {
    const fingerprint = this.computeFingerprint(signals);
    const devicesKey = `devices:${tenantId}:${userId}`;

    try {
      const [isKnown, knownDevices] = await Promise.all([
        this.cache.sismember(devicesKey, fingerprint),
        this.cache.smembers(devicesKey),
      ]);

      if (isKnown) {
        return { score: 0.0, fingerprint };
      }

      // Unknown device
      const hasExistingDevices = knownDevices.length > 0;
      const score = hasExistingDevices ? 0.5 : 0.1;
      return { score, fingerprint };
    } catch (err) {
      this.logger.warn({ err }, 'DeviceAnalyzer failed — using 0.0');
      return { score: 0.0, fingerprint };
    }
  }

  /**
   * Registers a device fingerprint as trusted for a user.
   * Called after successful MFA verification (Req 8.10).
   */
  async trustDevice(fingerprint: string, tenantId: string, userId: string): Promise<void> {
    const devicesKey = `devices:${tenantId}:${userId}`;
    await this.cache.sadd(devicesKey, fingerprint).catch((err) =>
      this.logger.warn({ err }, 'Failed to register trusted device'),
    );
  }

  /**
   * Computes a stable 32-char hex device fingerprint.
   * SHA-256(ua:lang:screen:tz:platform).slice(0, 16) → 32 hex chars
   */
  computeFingerprint(signals: DeviceSignals): string {
    const raw = [
      signals.userAgent,
      signals.acceptLanguage ?? '',
      signals.screenResolution ?? '',
      signals.timezone ?? '',
      signals.platform ?? '',
    ].join(':');

    return createHash('sha256').update(raw).digest('hex').slice(0, 32);
  }
}
