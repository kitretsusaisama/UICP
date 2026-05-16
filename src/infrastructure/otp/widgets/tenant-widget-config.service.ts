import { Inject, Injectable, Logger } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'crypto';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { ICachePort } from '../../../application/ports/driven/i-cache.port';
import { ITenantOtpWidgetRepository } from '../../../application/ports/driven/i-otp-widget.port';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { DomainErrorCode } from '../../../domain/exceptions/domain-error-codes';
import { TenantIsolationGuard } from '../isolation/tenant-isolation-guard';

export interface WidgetConfigResponse {
  widgetId: string;
  tokenAuth: string;
  theme: Record<string, unknown>;
  layout: Record<string, unknown>;
  behavior: Record<string, unknown>;
  localization: Record<string, unknown>;
  channels: string[];
  isolationSignature: string;
}

@Injectable()
export class TenantWidgetConfigService {
  private readonly logger = new Logger(TenantWidgetConfigService.name);
  private readonly signatureSecret: string;

  constructor(
    private readonly isolationGuard: TenantIsolationGuard,
    @Inject(INJECTION_TOKENS.CACHE_PORT)
    private readonly cache: ICachePort,
    @Inject(INJECTION_TOKENS.OTP_WIDGET_REPO)
    private readonly widgetRepo: ITenantOtpWidgetRepository,
  ) {
    this.signatureSecret = process.env.WIDGET_SIGNATURE_SECRET ?? 'uicp-widget-secret-key';
  }

  async getWidgetConfig(tenantId: string): Promise<WidgetConfigResponse> {
    await this.isolationGuard.validateTenantAccess({
      tenantId,
      operation: 'CONFIGURE',
    });

    const cacheKey = `widget-config:${tenantId}`;
    const cached = await this.cache.get(cacheKey);

    if (cached) {
      return JSON.parse(cached);
    }

    const config = await this.widgetRepo.findByTenantId(tenantId);

    if (!config) {
      throw new DomainException(
        DomainErrorCode.WIDGET_NOT_CONFIGURED,
        `Tenant ${tenantId} does not have OTP widget configured`,
      );
    }

    const tokenAuth = await this.getTokenFromVault(tenantId, config.tokenAuthEncrypted);

    const signature = this.generateSignature({
      widgetId: config.widgetId,
      tokenAuth,
      theme: config.themeConfig,
      layout: config.layoutConfig,
      behavior: config.behaviorConfig,
      localization: config.localization,
      channels: config.allowedChannels,
    }, tenantId);

    const response: WidgetConfigResponse = {
      widgetId: config.widgetId,
      tokenAuth,
      theme: config.themeConfig,
      layout: config.layoutConfig,
      behavior: config.behaviorConfig,
      localization: config.localization,
      channels: config.allowedChannels,
      isolationSignature: signature,
    };

    await this.cache.set(cacheKey, JSON.stringify(response), 3600);

    this.logger.debug({ tenantId }, 'Widget config retrieved');
    return response;
  }

  async validateWidgetConfig(config: WidgetConfigResponse, tenantId: string): Promise<boolean> {
    const signature = config.isolationSignature;
    const expectedSignature = this.generateSignature(
      { ...config, isolationSignature: undefined },
      tenantId,
    );

    const signatureBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');

    if (signatureBuffer.length !== expectedBuffer.length) {
      return false;
    }

    return timingSafeEqual(signatureBuffer, expectedBuffer);
  }

  async updateWidgetConfig(
    tenantId: string,
    config: {
      providerName?: string;
      widgetId?: string;
      tokenAuthEncrypted?: string;
      themeConfig?: Record<string, unknown>;
      layoutConfig?: Record<string, unknown>;
      behaviorConfig?: Record<string, unknown>;
      localization?: Record<string, unknown>;
      allowedOrigins?: string[];
      allowedChannels?: string[];
    },
  ): Promise<void> {
    await this.isolationGuard.validateTenantAccess({
      tenantId,
      operation: 'CONFIGURE',
    });

    await this.widgetRepo.update(tenantId, config);

    await this.cache.del(`widget-config:${tenantId}`);
    await this.cache.del(`widget-token:${tenantId}`);

    this.logger.debug({ tenantId }, 'Widget config updated');
  }

  async getWidgetInitScript(tenantId: string): Promise<string> {
    const config = await this.getWidgetConfig(tenantId);

    return `
(function() {
  if (window.UICPWidget) return;

  window.UICPWidget = {
    config: ${JSON.stringify(config)},
    initialized: false,

    init: function() {
      if (this.initialized) return;
      // Widget initialized - removed client-side debug log
      this.initialized = true;
    },

    send: function(mobile) {
      return fetch('/v1/auth/otp/widget/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': '${tenantId}'
        },
        body: JSON.stringify({ tenantId: '${tenantId}', identity: mobile })
      }).then(r => r.json());
    },

    verify: function(otp, challengeId) {
      return fetch('/v1/auth/otp/widget/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': '${tenantId}'
        },
        body: JSON.stringify({
          tenantId: '${tenantId}',
          providerToken: otp,
          challengeId: challengeId
        })
      }).then(r => r.json());
    }
  };

  window.UICPWidget.init();
})();
    `.trim();
  }

  private generateSignature(data: object, tenantId: string): string {
    const payload = JSON.stringify(data);
    const hmac = createHmac('sha256', this.signatureSecret);
    hmac.update(`${tenantId}:${payload}`);
    return hmac.digest('hex');
  }

  private async getTokenFromVault(tenantId: string, encryptedRef: string): Promise<string> {
    const cacheKey = `widget-token:${tenantId}`;
    const cached = await this.cache.get(cacheKey);

    if (cached) {
      return cached;
    }

    // In production, resolve from vault using encryptedRef
    // For now, decode the ref as base64 or use mock
    let token = '';

    try {
      const decoded = Buffer.from(encryptedRef, 'base64').toString('utf8');
      if (decoded.startsWith('tok_')) {
        token = decoded;
      } else {
        token = `tok_${tenantId.slice(0, 8)}_${Date.now()}`;
      }
    } catch {
      token = `tok_${tenantId.slice(0, 8)}_${Date.now()}`;
    }

    await this.cache.set(cacheKey, token, 86400);
    return token;
  }
}