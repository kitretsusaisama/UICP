import { Module } from '@nestjs/common';

// Infrastructure modules (provide the ports that application services depend on)
import { RepositoriesModule } from '../infrastructure/db/mysql/repositories.module';
import { SessionModule } from '../infrastructure/session/session.module';
import { LockModule } from '../infrastructure/lock/lock.module';
import { OtpModule } from '../infrastructure/otp/otp.module';
import { QueueModule } from '../infrastructure/queue/queue.module';
import { LoggerModule } from '../shared/logger/logger.module';

// Application services
import { CredentialService } from './services/credential.service';
import { TokenService } from './services/token.service';
import { SessionService } from './services/session.service';
import { OtpService } from './services/otp.service';
import { DistributedLockService } from './services/distributed-lock.service';
import { IdempotencyService } from './services/idempotency.service';
import { RuntimeIdentityService } from './services/runtime-identity.service';
import { RuntimeAuthorizationService } from './services/runtime-authorization.service';

// Platform Services
import { AppService } from './services/platform/app.service';
import { AppSecretService } from './services/platform/app-secret.service';
import { DomainService } from './services/platform/domain.service';
import { WebhookService } from './services/platform/webhook.service';
import { OAuthService } from './services/platform/oauth.service';

// Governance Services
import { RoleService } from './services/governance/role.service';
import { PolicyService } from './services/governance/policy.service';

// Command handlers
import { SignupEmailHandler } from './commands/signup-email/signup-email.handler';
import { SignupPhoneHandler } from './commands/signup-phone/signup-phone.handler';
import { LoginHandler } from './commands/login/login.handler';
import { RefreshTokenHandler } from './commands/refresh-token/refresh-token.handler';
import { VerifyOtpHandler } from './commands/verify-otp/verify-otp.handler';
import { LogoutHandler } from './commands/logout/logout.handler';
import { LogoutAllHandler } from './commands/logout-all/logout-all.handler';
import { OAuthCallbackHandler } from './commands/oauth-callback/oauth-callback.handler';
import { ChangePasswordHandler } from './commands/change-password/change-password.handler';
import { PasswordResetRequestHandler } from './commands/password-reset-request/password-reset-request.handler';
import { PasswordResetConfirmHandler } from './commands/password-reset-confirm/password-reset-confirm.handler';
import { RotateKeysHandler } from './commands/rotate-keys/rotate-keys.handler';

// Query handlers
import { GetUserHandler } from './queries/get-user/get-user.handler';
import { GetUserSessionsHandler } from './queries/get-user-sessions/get-user-sessions.handler';
import { GetJwksHandler } from './queries/get-jwks/get-jwks.handler';
import { ValidateTokenHandler } from './queries/validate-token/validate-token.handler';
import { GetThreatHistoryHandler } from './queries/get-threat-history/get-threat-history.handler';
import { ListAuditLogsHandler } from './queries/list-audit-logs/list-audit-logs.handler';

// Sagas
import { IdentityVerificationSaga } from './sagas/identity-verification.saga';

// ABAC
import { AbacPolicyEngine } from './services/abac/abac-policy-engine';
import { TenantManifestService } from './control-plane/services/tenant-manifest.service';
import { ProviderRoutingService } from './control-plane/services/provider-routing.service';
import { ExtensionDispatcherService } from './dynamic-api/services/extension-dispatcher.service';
import { DynamicCommandRegistryService } from './dynamic-api/services/dynamic-command-registry.service';

const SERVICES = [
  CredentialService,
  TokenService,
  SessionService,
  OtpService,
  DistributedLockService,
  IdempotencyService,
  RuntimeIdentityService,
  RuntimeAuthorizationService,
  TenantManifestService,
  ProviderRoutingService,
  ExtensionDispatcherService,
  DynamicCommandRegistryService,
  AppService,
  AppSecretService,
  DomainService,
  WebhookService,
  OAuthService,
  RoleService,
  PolicyService,
];

const COMMAND_HANDLERS = [
  SignupEmailHandler,
  SignupPhoneHandler,
  LoginHandler,
  RefreshTokenHandler,
  VerifyOtpHandler,
  LogoutHandler,
  LogoutAllHandler,
  OAuthCallbackHandler,
  ChangePasswordHandler,
  PasswordResetRequestHandler,
  PasswordResetConfirmHandler,
  RotateKeysHandler,
];

const QUERY_HANDLERS = [
  GetUserHandler,
  GetUserSessionsHandler,
  GetJwksHandler,
  ValidateTokenHandler,
  GetThreatHistoryHandler,
  ListAuditLogsHandler,
];

/**
 * ApplicationModule — wires all application services, command handlers,
 * query handlers, and sagas. Depends on infrastructure modules for ports.
 */
@Module({
  imports: [
    RepositoriesModule,
    SessionModule,
    LockModule,
    OtpModule,
    QueueModule,
    LoggerModule,
  ],
  providers: [
    ...SERVICES,
    ...COMMAND_HANDLERS,
    ...QUERY_HANDLERS,
    IdentityVerificationSaga,
    AbacPolicyEngine,
  ],
  exports: [
    ...SERVICES,
    ...COMMAND_HANDLERS,
    ...QUERY_HANDLERS,
    AbacPolicyEngine,
    QueueModule,
    OtpModule,
  ],
})
export class ApplicationModule {}
