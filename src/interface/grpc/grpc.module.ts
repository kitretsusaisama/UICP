import { Module } from '@nestjs/common';
import { TokenValidateGrpcHandler } from './token-validate.grpc.handler';
import { AuthGrpcHandler } from './auth.grpc.handler';
import { ApplicationModule } from '../../application/application.module';

/**
 * GrpcModule — registers gRPC handlers for internal service-to-service
 * communication on port 5000 (Section 17.7).
 *
 * Exposes:
 *   - ValidateToken RPC  (TokenValidateGrpcHandler)
 *   - CheckPermission RPC (AuthGrpcHandler)
 *   - GetUserClaims RPC   (AuthGrpcHandler)
 *
 * Implements: Req 7.10, Req 16.6
 */
@Module({
  imports: [ApplicationModule],
  providers: [
    TokenValidateGrpcHandler,
    AuthGrpcHandler,
  ],
  exports: [TokenValidateGrpcHandler, AuthGrpcHandler],
})
export class GrpcModule {}
