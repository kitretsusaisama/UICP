import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'crypto';
import { OtpSendParams, OtpVerifyParams } from '../universal-otp-kernel';
import { Channel } from '../../adaptive/tenant-adaptive-engine';

export interface Msg91WidgetConfig {
  widgetId: string;
  flowId: string;
  senderId: string;
  templateId?: string;
}

export interface Msg91ProviderAdapter {
  key: string;
  name: string;
  channels: Channel[];
  capabilities: string[];
  hasNativeWidget: boolean;
}

@Injectable()
export class Msg91WidgetProvider {
  private readonly logger = new Logger(Msg91WidgetProvider.name);

  readonly key = 'msg91';
  readonly name = 'MSG91';
  readonly channels: Channel[] = ['SMS', 'WHATSAPP', 'VOICE', 'EMAIL'];
  readonly capabilities = ['widget', 'api', 'whatsapp', 'voice'];
  readonly hasNativeWidget = true;

  constructor(private readonly config: ConfigService) {}

  /**
   * Send OTP via MSG91 Widget API.
   * Note: For widget mode, this is called when backend needs to send OTP directly.
   */
  async sendOtp(params: OtpSendParams & { challengeId: string; code?: string }): Promise<{ providerMessageId?: string }> {
    const apiKey = this.config.get<string>('MSG91_AUTH_KEY');
    const senderId = this.config.get<string>('MSG91_SENDER_ID');

    if (!apiKey || !senderId) {
      this.logger.warn('MSG91 not configured, skipping send');
      return { providerMessageId: 'mock-msg91-success' };
    }

    // For widget mode, the actual sending is handled by the widget on frontend
    // This is only called for non-widget flow or fallback
    const flowId = this.getFlowIdForPurpose(params.purpose);

    const body = {
      sender: senderId,
      flow_id: flowId,
      recipients: [
        {
          mobile: params.identity.replace(/^\+/, ''),
          otp: params.code,
        },
      ],
    };

    try {
      const response = await fetch('https://control.msg91.com/api/v5/flow/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'authkey': apiKey,
        },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        throw new Error(`MSG91 API error: ${response.status}`);
      }

      const payload = await response.json() as { request_id?: string };
      this.logger.debug({ requestId: payload.request_id }, 'OTP sent via MSG91');

      return { providerMessageId: payload.request_id };
    } catch (error) {
      this.logger.error({ error: (error as Error).message }, 'Failed to send OTP via MSG91');
      throw error;
    }
  }

  /**
   * Verify widget access token from MSG91.
   */
  async verifyToken(params: OtpVerifyParams): Promise<{ valid: boolean; identity?: string }> {
    const { providerToken, challengeId } = params;

    if (!providerToken) {
      return { valid: false };
    }

    // In a real implementation, this would verify the token with MSG91 API
    // For now, simulate verification
    const isValid = this.validateTokenFormat(providerToken);

    if (!isValid) {
      return { valid: false };
    }

    // Decode token to get identity (in real impl, verify with MSG91)
    const identity = this.extractIdentityFromToken(providerToken);

    return {
      valid: true,
      identity,
    };
  }

  /**
   * Get widget configuration for tenant.
   */
  async getWidgetConfig(tenantId: string): Promise<{ widgetId: string; tokenAuth: string }> {
    // In a real implementation, this would fetch from TenantWidgetConfigService
    // For now, return config from environment
    return {
      widgetId: this.config.get<string>('MSG91_WIDGET_ID') ?? `widget_${tenantId.slice(0, 8)}`,
      tokenAuth: this.config.get<string>('MSG91_TOKEN_AUTH') ?? `token_${tenantId.slice(0, 8)}`,
    };
  }

  /**
   * Initialize MSG91 widget script for frontend.
   */
  getWidgetInitScript(config: { widgetId: string; tokenAuth: string }): string {
    return `
(function() {
  if (window.MSG91Widget) return;

  window.MSG91Widget = {
    config: ${JSON.stringify(config)},
    initialized: false,

    init: function() {
      if (this.initialized) return;

      // Load MSG91 widget script dynamically
      var script = document.createElement('script');
      script.src = 'https://widget.msg91.com/assets/js/widget.js';
      script.async = true;
      script.onload = () => this.setupWidget();
      document.head.appendChild(script);

      this.initialized = true;
    },

    setupWidget: function() {
      if (typeof window.sendOtp !== 'function') {
        // MSG91 widget not loaded - this is expected if widget script fails to load
        return;
      }

      window.sendOtp = window.sendOtp || function(mobile, onSuccess, onError) {
        // Widget handles OTP sending
      };

      window.verifyOtp = window.verifyOtp || function(otp, onSuccess, onError) {
        // Widget handles OTP verification
      };

      window.retryOtp = window.retryOtp || function(channel, onSuccess, onError) {
        // Widget handles OTP retry
      };
    },

    send: function(mobile) {
      return new Promise((resolve, reject) => {
        window.sendOtp(mobile, resolve, reject);
      });
    },

    verify: function(otp) {
      return new Promise((resolve, reject) => {
        window.verifyOtp(otp, resolve, reject);
      });
    },

    retry: function(channel) {
      return new Promise((resolve, reject) => {
        window.retryOtp(channel, resolve, reject);
      });
    }
  };

  // Auto-initialize
  window.MSG91Widget.init();
})();
    `.trim();
  }

  // Private helpers

  private getFlowIdForPurpose(purpose: string): string {
    const flowIds: Record<string, string> = {
      IDENTITY_VERIFICATION: this.config.get<string>('MSG91_FLOW_ID_IDENTITY') ?? 'DEFAULT',
      MFA: this.config.get<string>('MSG91_FLOW_ID_MFA') ?? 'DEFAULT',
      PASSWORD_RESET: this.config.get<string>('MSG91_FLOW_ID_PASSWORD_RESET') ?? 'DEFAULT',
    };
    return flowIds[purpose] ?? 'DEFAULT';
  }

  private validateTokenFormat(token: string): boolean {
    // Basic format validation - in real impl, verify with MSG91 API
    // Widget tokens are typically alphanumeric strings
    return token.length >= 10 && /^[a-zA-Z0-9_-]+$/.test(token);
  }

  private extractIdentityFromToken(token: string): string {
    // In a real implementation, this would decode/verify with MSG91
    // For mock purposes, extract from token
    return `user_${token.slice(0, 8)}`;
  }
}

@Injectable()
export class Msg91WidgetProviderModule {
  static forRoot() {
    return {
      module: Msg91WidgetProviderModule,
      providers: [Msg91WidgetProvider],
      exports: [Msg91WidgetProvider],
    };
  }
}