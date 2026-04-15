import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OtpPurpose } from '../../application/ports/driven/i-otp.port';

export interface TemplateBranding {
  brandName: string;
  logoUrl?: string;
  supportEmail?: string;
  accentColor: string;
  footerText: string;
}

export interface TemplateContent {
  subject: string;
  text: string;
  html: string;
}

@Injectable()
export class NotificationTemplateService {
  constructor(private readonly config: ConfigService) {}

  buildOtpTemplate(params: {
    purpose: OtpPurpose;
    code: string;
    tenantName?: string;
  }): TemplateContent {
    const branding = this.getBranding(params.tenantName);
    const heading = this.headingForPurpose(params.purpose, branding.brandName);
    const intro = this.introForPurpose(params.purpose, branding.brandName);
    const subject = this.subjectForPurpose(params.purpose, branding.brandName);
    const text = [
      `${heading}`,
      '',
      `${intro}: ${params.code}`,
      '',
      'This credential expires in 5 minutes.',
      branding.supportEmail ? `Need help? Contact ${branding.supportEmail}.` : undefined,
      branding.footerText,
    ]
      .filter(Boolean)
      .join('\n');

    const logoBlock = branding.logoUrl
      ? `<img src="${branding.logoUrl}" alt="${branding.brandName}" style="max-height:40px;margin-bottom:16px" />`
      : '';

    const html = `
      <div style="background:#f6f8fb;padding:32px 16px;font-family:Arial,sans-serif;color:#10203a">
        <div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:18px;padding:32px;border:1px solid #e6ebf2">
          ${logoBlock}
          <p style="margin:0 0 12px 0;font-size:13px;letter-spacing:0.12em;text-transform:uppercase;color:${branding.accentColor}">
            ${branding.brandName}
          </p>
          <h1 style="margin:0 0 12px 0;font-size:24px;line-height:1.3">${heading}</h1>
          <p style="margin:0 0 20px 0;font-size:15px;line-height:1.6">${intro}</p>
          <div style="display:inline-block;padding:16px 20px;border-radius:14px;background:#0f172a;color:#ffffff;font-size:28px;letter-spacing:0.28em;font-family:Consolas,Monaco,monospace">
            ${params.code}
          </div>
          <p style="margin:20px 0 8px 0;font-size:14px;line-height:1.6">This credential expires in <strong>5 minutes</strong>.</p>
          ${
            branding.supportEmail
              ? `<p style="margin:0 0 12px 0;font-size:14px;line-height:1.6">Need help? Contact <a href="mailto:${branding.supportEmail}" style="color:${branding.accentColor}">${branding.supportEmail}</a>.</p>`
              : ''
          }
          <p style="margin:0;color:#64748b;font-size:12px;line-height:1.6">${branding.footerText}</p>
        </div>
      </div>
    `.trim();

    return { subject, text, html };
  }

  private getBranding(tenantName?: string): TemplateBranding {
    const brandName =
      tenantName ??
      this.config.get<string>('MAIL_BRAND_NAME') ??
      'Unified Identity Control Plane';
    return {
      brandName,
      logoUrl: this.config.get<string>('MAIL_LOGO_URL'),
      supportEmail: this.config.get<string>('MAIL_SUPPORT_EMAIL') ?? this.config.get<string>('SMTP_FROM'),
      accentColor: this.config.get<string>('MAIL_ACCENT_COLOR') ?? '#1d4ed8',
      footerText:
        this.config.get<string>('MAIL_FOOTER_TEXT') ??
        'If you did not request this message, you can safely ignore it.',
    };
  }

  private subjectForPurpose(purpose: OtpPurpose, brandName: string): string {
    switch (purpose) {
      case 'IDENTITY_VERIFICATION':
        return `Verify your ${brandName} account`;
      case 'MFA':
        return `Your ${brandName} login code`;
      case 'PASSWORD_RESET':
        return `Reset your ${brandName} password`;
      default:
        return `Your ${brandName} code`;
    }
  }

  private headingForPurpose(purpose: OtpPurpose, brandName: string): string {
    switch (purpose) {
      case 'IDENTITY_VERIFICATION':
        return `Verify your ${brandName} account`;
      case 'MFA':
        return 'Complete your sign-in';
      case 'PASSWORD_RESET':
        return 'Reset your password';
      default:
        return 'Your secure code';
    }
  }

  private introForPurpose(purpose: OtpPurpose, brandName: string): string {
    switch (purpose) {
      case 'IDENTITY_VERIFICATION':
        return `Use this verification code to activate your ${brandName} account`;
      case 'MFA':
        return `Use this one-time code to continue signing in to ${brandName}`;
      case 'PASSWORD_RESET':
        return `Use this one-time code to reset your ${brandName} password`;
      default:
        return `Use this one-time code for ${brandName}`;
    }
  }
}
