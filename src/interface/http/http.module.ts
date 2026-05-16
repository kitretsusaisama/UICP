import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { ApplicationModule } from '../../application/application.module';
import { CommunicationController } from './controllers/communication/communication.controller';
import { AdminController } from './controllers/admin.controller';
import { AuthCoreController, AuthOtpController, AuthPasswordController, AuthOAuthController, UnifiedAuthController } from './controllers/auth';
import { CoreController } from './controllers/core.controller';
import { DynamicModuleController } from './controllers/dynamic-module.controller';
import { ExtensionController } from './controllers/extension.controller';
import { IamController } from './controllers/iam.controller';
import { JwksController } from './controllers/jwks.controller';
import { PlatformController } from './controllers/platform.controller';
import { SessionController } from './controllers/session.controller';
import { UserController } from './controllers/user.controller';
import { AppController } from './controllers/platform/app.controller';
import { AppSecretController } from './controllers/platform/app-secret.controller';
import { DomainController } from './controllers/platform/domain.controller';
import { OAuthController } from './controllers/platform/oauth.controller';
import { WebhookController } from './controllers/platform/webhook.controller';
import { PolicyController } from './controllers/governance/policy.controller';
import { RoleController } from './controllers/governance/role.controller';
import { OtpWidgetController } from './controllers/otp.controller';
import { TenantApiKeyController } from './controllers/tenant-api-key.controller';
import { ApiKeyController } from './controllers/api-key.controller';
import { ApiKeyGuard } from './guards/api-key.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { UnifiedAuthGuard } from './guards/unified-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { TenantGuard } from './guards/tenant.guard';
import { ClsContextInterceptor } from './interceptors/cls-context.interceptor';
import { IdempotencyInterceptor } from './interceptors/idempotency.interceptor';
import { ResponseEnvelopeInterceptor } from './interceptors/response-envelope.interceptor';
import { GlobalExceptionFilter } from './filters/global-exception.filter';
import { RateLimiterMiddleware } from './middleware/rate-limiter.middleware';
import { ApiMetricsMiddleware } from './middleware/api-metrics.middleware';
import { HealthController } from './controllers/health.controller';

@Module({
  imports: [ApplicationModule],
  controllers: [
    CommunicationController,
    HealthController,
    TenantApiKeyController,
    ApiKeyController,
    AuthCoreController,
    AuthOtpController,
    AuthPasswordController,
    AuthOAuthController,
    UnifiedAuthController,
    AdminController,
    JwksController,
    IamController,
    CoreController,
    PlatformController,
    DynamicModuleController,
    ExtensionController,
    SessionController,
    UserController,
    AppController,
    AppSecretController,
    DomainController,
    OAuthController,
    RoleController,
    PolicyController,
    OtpWidgetController,
  ],
  providers: [
    ApiKeyGuard,
    JwtAuthGuard,
    UnifiedAuthGuard,
    TenantGuard,
    RolesGuard,
    { provide: APP_FILTER, useClass: GlobalExceptionFilter },
    { provide: APP_INTERCEPTOR, useClass: ClsContextInterceptor },
    { provide: APP_INTERCEPTOR, useClass: IdempotencyInterceptor },
    { provide: APP_INTERCEPTOR, useClass: ResponseEnvelopeInterceptor },
  ],
  exports: [ApiKeyGuard, JwtAuthGuard, UnifiedAuthGuard, TenantGuard, RolesGuard],
})
export class HttpModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(ApiMetricsMiddleware, RateLimiterMiddleware)
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}
