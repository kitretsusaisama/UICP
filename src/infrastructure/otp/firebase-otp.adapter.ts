import { Injectable, Logger, Optional, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { IOtpPort, SendOtpParams } from '../../application/ports/driven/i-otp.port';
import { CircuitBreaker, CIRCUIT_BREAKER_CONFIGS } from '../resilience/circuit-breaker';
import { IMetricsPort } from '../../application/ports/driven/i-metrics.port';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';

/**
 * Firebase OTP adapter — SMS delivery via Firebase Cloud Messaging / Firebase Auth.
 *
 * Implements IOtpPort for the SMS channel.
 * Wrapped with a circuit breaker: 3000ms timeout, 40% error threshold (Req 15.1).
 *
 * When the circuit is OPEN, throws so the caller can fall back to SMTP.
 */
@Injectable()
export class FirebaseOtpAdapter implements IOtpPort {
  private readonly logger = new Logger(FirebaseOtpAdapter.name);

  // ── Circuit Breaker ────────────────────────────────────────────────────────
  private readonly circuitBreaker: CircuitBreaker<void>;

  constructor(
    private readonly config: ConfigService,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {
    this.circuitBreaker = new CircuitBreaker(CIRCUIT_BREAKER_CONFIGS.firebase, metrics);
  }

  /**
   * Send an OTP via SMS using Firebase.
   * Only handles the SMS channel — throws for EMAIL channel.
   */
  async send(params: SendOtpParams): Promise<void> {
    if (params.channel !== 'SMS') {
      throw new Error('FirebaseOtpAdapter only handles SMS channel');
    }

    // WAR-GRADE DEFENSE: Validate phone number format to prevent sending to virtual/VoIP/premium
    // using basic regex. In a real system, use libphonenumber-js to thoroughly validate.
    if (!/^\+[1-9]\d{7,14}$/.test(params.recipient)) {
      this.logger.warn({ recipient: params.recipient }, 'SMS Dispatch Blocked: Invalid E.164 phone number format');
      throw new Error('OTP_DELIVERY_FAILED: Invalid phone number format');
    }

    await this.circuitBreaker.execute(() => this.dispatchSms(params));
  }

  /**
   * Whether the circuit breaker is currently OPEN.
   * Used by the composite adapter to decide fallback routing.
   */
  isCircuitOpen(): boolean {
    return this.circuitBreaker.isOpen();
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private async dispatchSms(params: SendOtpParams): Promise<void> {
    const projectId = this.config.get<string>('FIREBASE_PROJECT_ID');
    const clientEmail = this.config.get<string>('FIREBASE_CLIENT_EMAIL');
    const privateKey = this.config.get<string>('FIREBASE_PRIVATE_KEY');

    if (!projectId || !clientEmail || !privateKey) {
      throw new Error(
        'Firebase configuration missing: FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY are all required',
      );
    }

    // Build the SMS message body based on purpose
    const message = this.buildSmsMessage(params);

    // Firebase Admin SDK — dynamically required to avoid hard dependency at startup
    // when Firebase is not configured (e.g. in test environments).
    let admin: any;
    try {
      admin = require('firebase-admin');
    } catch {
      throw new Error('firebase-admin package not installed. Run: npm install firebase-admin');
    }

    // Initialize once per process — guard against duplicate app registration.
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId,
          clientEmail,
          // .env stores \n as literal backslash-n — unescape to real newlines.
          privateKey: privateKey.replace(/\\n/g, '\n'),
        }),
      });
    }

    // Firebase Cloud Messaging: send a data message to a phone-number-scoped topic.
    // The mobile client subscribes to `otp-{e164}` and displays the code locally.
    // Timeout is enforced by the CircuitBreaker wrapper (CIRCUIT_BREAKER_CONFIGS.firebase.timeoutMs).
    await admin.messaging().send({
      topic: `otp-${params.recipient.replace(/\+/g, '')}`,
      data: {
        code: params.code,
        purpose: params.purpose,
        tenantName: params.tenantName ?? '',
        message,
      },
    });

    this.logger.log(
      { recipient: '[REDACTED]', purpose: params.purpose },
      'OTP SMS dispatched via Firebase',
    );
  }

  private buildSmsMessage(params: SendOtpParams): string {
    const tenant = params.tenantName ?? 'the service';
    switch (params.purpose) {
      case 'IDENTITY_VERIFICATION':
        return `Your ${tenant} verification code is: ${params.code}. Valid for 5 minutes.`;
      case 'MFA':
        return `Your ${tenant} login code is: ${params.code}. Valid for 5 minutes.`;
      case 'PASSWORD_RESET':
        return `Your ${tenant} password reset code is: ${params.code}. Valid for 5 minutes.`;
      default:
        return `Your ${tenant} code is: ${params.code}. Valid for 5 minutes.`;
    }
  }
}
