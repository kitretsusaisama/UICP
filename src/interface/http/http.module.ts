import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { ApplicationModule } from '../../application/application.module';

// Controllers
import { AuthController } from './controllers/auth.controller';
import { AdminController } from './controllers/admin.controller';
import { JwksController } from './controllers/jwks.controller';
import { IamController } from './controllers/iam.controller';
import { PlatformController } from './controllers/platform.controller';
import { DynamicModuleController } from './controllers/dynamic-module.controller';
import { ExtensionController } from './controllers/extension.controller';
import { CoreController } from './controllers/core.controller';

// Guards, interceptors, filters, pipes
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { IdempotencyInterceptor } from './interceptors/idempotency.interceptor';
import { ResponseEnvelopeInterceptor } from './interceptors/response-envelope.interceptor';
import { ClsContextInterceptor } from './interceptors/cls-context.interceptor';
import { GlobalExceptionFilter } from './filters/global-exception.filter';
import { RateLimiterMiddleware } from './middleware/rate-limiter.middleware';

// ABAC policy engine — moved to ApplicationModule
// import { AbacPolicyEngine } from '../../application/services/abac/abac-policy-engine';

@Module({
  imports: [ApplicationModule],
  controllers: [
    AuthController,
    AdminController,
    JwksController,
    IamController,
    CoreController,
    PlatformController,
    DynamicModuleController,
    ExtensionController,
  ],
  providers: [
    JwtAuthGuard,
    // Global exception filter
    { provide: APP_FILTER, useClass: GlobalExceptionFilter },
    // Global interceptors (order matters: envelope wraps idempotency)
    { provide: APP_INTERCEPTOR, useClass: ClsContextInterceptor },
    { provide: APP_INTERCEPTOR, useClass: IdempotencyInterceptor },
    { provide: APP_INTERCEPTOR, useClass: ResponseEnvelopeInterceptor },
  ],
  exports: [JwtAuthGuard],
})
export class HttpModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(RateLimiterMiddleware)
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}
