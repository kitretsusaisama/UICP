import { Module } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { NotificationTemplateService } from './notification-template.service';
import { Msg91SmsProvider } from '../providers/sms/msg91-sms.provider';
import { ResendEmailProvider } from '../providers/email/resend-email.provider';
import { MailerooEmailProvider } from '../providers/email/maileroo-email.provider';
import { ProviderRegistryService } from '../providers/provider-registry.service';
import { NotificationDispatcherService } from '../providers/notification-dispatcher.service';
import { ProviderRoutingService } from '../../application/control-plane/services/provider-routing.service';
import { RepositoriesModule } from '../db/mysql/repositories.module';

// New OTP isolation components
import { TenantIsolationGuard } from './isolation/tenant-isolation-guard';
import { TenantProviderRegistry } from './registry/tenant-provider-registry';
import { TenantAdaptiveEngine } from './adaptive/tenant-adaptive-engine';
import { TenantWidgetConfigService } from './widgets/tenant-widget-config.service';
import { TenantRiskScorer } from './security/tenant-risk-scorer';
import { UniversalOtpKernel } from './kernel/universal-otp-kernel';
import { Msg91WidgetProvider } from './kernel/providers/msg91-widget.provider';

import { MysqlOtpProviderRepository } from '../db/mysql/mysql-otp-provider.repository';
import { MysqlOtpWidgetRepository } from '../db/mysql/mysql-otp-widget.repository';
import { MysqlOtpRiskPolicyRepository } from '../db/mysql/mysql-otp-risk-policy.repository';
import { MysqlOtpAdaptiveModelRepository } from '../db/mysql/mysql-otp-adaptive-model.repository';

@Module({
  imports: [RepositoriesModule],
  providers: [
    // Existing providers
    NotificationTemplateService,
    Msg91SmsProvider,
    ResendEmailProvider,
    MailerooEmailProvider,
    ProviderRegistryService,
    ProviderRoutingService,
    NotificationDispatcherService,
    { provide: INJECTION_TOKENS.OTP_PORT, useExisting: NotificationDispatcherService },

    // New OTP isolation components
    TenantIsolationGuard,
    TenantProviderRegistry,
    TenantAdaptiveEngine,
    TenantWidgetConfigService,
    TenantRiskScorer,
    UniversalOtpKernel,
    Msg91WidgetProvider,

    // Repository implementations
    MysqlOtpProviderRepository,
    MysqlOtpWidgetRepository,
    MysqlOtpRiskPolicyRepository,
    MysqlOtpAdaptiveModelRepository,

    // Bind repositories to injection tokens
    { provide: INJECTION_TOKENS.OTP_PROVIDER_REPO, useExisting: MysqlOtpProviderRepository },
    { provide: INJECTION_TOKENS.OTP_WIDGET_REPO, useExisting: MysqlOtpWidgetRepository },
    { provide: INJECTION_TOKENS.OTP_RISK_POLICY_REPO, useExisting: MysqlOtpRiskPolicyRepository },
    { provide: INJECTION_TOKENS.OTP_ADAPTIVE_MODEL_REPO, useExisting: MysqlOtpAdaptiveModelRepository },
  ],
  exports: [
    INJECTION_TOKENS.OTP_PORT,
    ProviderRegistryService,
    ProviderRoutingService,
    NotificationDispatcherService,
    TenantIsolationGuard,
    TenantProviderRegistry,
    TenantAdaptiveEngine,
    TenantWidgetConfigService,
    TenantRiskScorer,
    UniversalOtpKernel,
  ],
})
export class OtpModule {}