import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { IOtpPort, SendOtpParams } from '../../application/ports/driven/i-otp.port';
import { FirebaseOtpAdapter } from './firebase-otp.adapter';
import { NotificationTemplateService } from './notification-template.service';

/**
 * Composite OTP adapter — routes SMS to Firebase, email to SMTP.
 *
 * Acts as the primary IOtpPort implementation:
 * - EMAIL channel → SMTP (nodemailer)
 * - SMS channel → Firebase (with circuit breaker fallback to SMTP if Firebase is OPEN)
 *
 * Implements Req 6.1, Req 15.1 (fallback when Firebase circuit breaker is open).
 */
@Injectable()
export class SmtpOtpAdapter implements IOtpPort {
  private readonly logger = new Logger(SmtpOtpAdapter.name);
  private transporter!: nodemailer.Transporter;

  constructor(
    private readonly config: ConfigService,
    private readonly firebase: FirebaseOtpAdapter,
    private readonly templates: NotificationTemplateService,
  ) {
    this.transporter = nodemailer.createTransport({
      host: this.config.get<string>('SMTP_HOST', 'localhost'),
      port: this.config.get<number>('SMTP_PORT', 587),
      secure: this.config.get<string>('SMTP_SECURE', 'false') === 'true',
      auth: {
        user: this.config.get<string>('SMTP_USER'),
        pass: this.config.get<string>('SMTP_PASS') ?? this.config.get<string>('SMTP_PASSWORD'),
      },
      connectionTimeout: 5_000,
      greetingTimeout: 5_000,
      socketTimeout: 10_000,
    });
  }

  /**
   * Deliver an OTP via the appropriate channel.
   *
   * - EMAIL → SMTP always
   * - SMS → Firebase; falls back to SMTP email if Firebase circuit is OPEN
   *   (Req 15.2: fallback when circuit breaker trips open)
   */
  async send(params: SendOtpParams): Promise<void> {
    if (params.channel === 'EMAIL') {
      await this.sendEmail(params);
      return;
    }

    // SMS: try Firebase first; fall back to SMTP email if circuit is open
    if (this.firebase.isCircuitOpen()) {
      this.logger.warn(
        { purpose: params.purpose },
        'Firebase circuit OPEN — falling back to SMTP email for OTP delivery',
      );
      // Fallback: send to email if available, otherwise fail
      await this.sendSmsFallbackEmail(params);
      return;
    }

    try {
      await this.firebase.send(params);
    } catch (err: any) {
      if (err?.code === 'CIRCUIT_OPEN') {
        this.logger.warn('Firebase circuit opened mid-request — falling back to SMTP');
        await this.sendSmsFallbackEmail(params);
        return;
      }
      throw Object.assign(
        new Error(`OTP_DELIVERY_FAILED: SMS delivery failed — ${(err as Error).message}`),
        { code: 'OTP_DELIVERY_FAILED' },
      );
    }
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private async sendEmail(params: SendOtpParams): Promise<void> {
    const from = this.config.get<string>('SMTP_FROM', 'noreply@uicp.local');
    const { subject, html, text } = this.templates.buildOtpTemplate({
      purpose: params.purpose,
      code: params.code,
      tenantName: params.tenantName,
    });

    try {
      await this.transporter.sendMail({
        from,
        to: params.recipient,
        subject,
        text,
        html,
      });

      this.logger.log(
        { purpose: params.purpose, channel: 'EMAIL' },
        'OTP email dispatched via SMTP',
      );
    } catch (err) {
      this.logger.error({ err, purpose: params.purpose }, 'SMTP OTP delivery failed');
      throw Object.assign(
        new Error(`OTP_DELIVERY_FAILED: SMTP delivery failed — ${(err as Error).message}`),
        { code: 'OTP_DELIVERY_FAILED' },
      );
    }
  }

  /**
   * SMS fallback: when Firebase is unavailable, attempt to deliver the OTP
   * via email if the recipient looks like an email address, otherwise fail.
   */
  private async sendSmsFallbackEmail(params: SendOtpParams): Promise<void> {
    // If recipient is a phone number (E.164), we cannot fall back to email
    // without a phone-to-email mapping. Throw a clear error.
    if (params.recipient.startsWith('+')) {
      throw Object.assign(
        new Error(
          'OTP_DELIVERY_FAILED: Firebase unavailable and no email fallback for phone-only recipient',
        ),
        { code: 'OTP_DELIVERY_FAILED' },
      );
    }
    // Treat as email fallback
    await this.sendEmail({ ...params, channel: 'EMAIL' });
  }

}
