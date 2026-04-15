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

@Module({
  imports: [RepositoriesModule],
  providers: [
    NotificationTemplateService,
    Msg91SmsProvider,
    ResendEmailProvider,
    MailerooEmailProvider,
    ProviderRegistryService,
    ProviderRoutingService,
    NotificationDispatcherService,
    { provide: INJECTION_TOKENS.OTP_PORT, useExisting: NotificationDispatcherService },
  ],
  exports: [INJECTION_TOKENS.OTP_PORT, ProviderRegistryService, ProviderRoutingService, NotificationDispatcherService],
})
export class OtpModule {}
