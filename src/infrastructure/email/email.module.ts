import { Module } from '@nestjs/common';
import { ResendEmailAdapter } from './adapters/resend/resend.adapter';
import { MailerooEmailAdapter } from './adapters/maileroo/maileroo.adapter';
import { SmtpEmailAdapter } from './adapters/smtp/smtp.adapter';
import { EmailProviderRegistry } from './registry/email-provider-registry';
import { EmailCircuitBreaker } from './circuit/email-circuit-breaker';
import { SmartRoutingEngine } from './resolver/smart-routing-engine';
import { EmailTrackingService } from './tracking/email-tracking.service';
import { EmailMetricsAggregator } from './metrics/email-metrics-aggregator';
import { EmailErrorHandler } from './exceptions/error-handler';

@Module({
  providers: [
    ResendEmailAdapter,
    MailerooEmailAdapter,
    SmtpEmailAdapter,
    EmailProviderRegistry,
    EmailCircuitBreaker,
    SmartRoutingEngine,
    EmailTrackingService,
    EmailMetricsAggregator,
    EmailErrorHandler,
  ],
  exports: [
    ResendEmailAdapter,
    MailerooEmailAdapter,
    SmtpEmailAdapter,
    EmailProviderRegistry,
    EmailCircuitBreaker,
    SmartRoutingEngine,
    EmailTrackingService,
    EmailMetricsAggregator,
    EmailErrorHandler,
  ],
})
export class EmailModule {}