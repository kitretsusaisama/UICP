import { QueueBackpressureGuard } from '../../guards/queue-backpressure.guard';
import {
  Body,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Inject,
  Logger,
  Post,
  Req,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { ApiHeader, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';

import { ChangePasswordCommand } from '@application/commands/change-password/change-password.command';
import { ChangePasswordHandler } from '@application/commands/change-password/change-password.handler';
import { PasswordResetRequestCommand } from '@application/commands/password-reset-request/password-reset-request.command';
import { PasswordResetRequestHandler } from '@application/commands/password-reset-request/password-reset-request.handler';
import { PasswordResetConfirmCommand } from '@application/commands/password-reset-confirm/password-reset-confirm.command';
import { PasswordResetConfirmHandler } from '@application/commands/password-reset-confirm/password-reset-confirm.handler';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { IdempotencyInterceptor } from '../../interceptors/idempotency.interceptor';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { changePasswordDto, passwordResetRequestDto, passwordResetConfirmDto } from '../../dtos';
import { parseTenantId } from '../../tenant/tenant-context';

// Helpers
interface AuthRequest {
  headers: Record<string, string | string[] | undefined>;
  principalId: string;
  userId: string;
  sessionId: string;
}

/**
 * Auth Password Controller
 * Handles: password/change, password/reset/request, password/reset/confirm
 */
@ApiTags('Auth - Password')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/auth/password')
@UseGuards(QueueBackpressureGuard)
export class AuthPasswordController {
  private readonly logger = new Logger(AuthPasswordController.name);

  constructor(
    private readonly changePasswordHandler: ChangePasswordHandler,
    private readonly passwordResetRequestHandler: PasswordResetRequestHandler,
    private readonly passwordResetConfirmHandler: PasswordResetConfirmHandler,
  ) {}

  // POST /auth/password/change
  @Post('change')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @UseInterceptors(IdempotencyInterceptor)
  async changePassword(
    @Req() req: AuthRequest,
    @Body(new ZodValidationPipe(changePasswordDto)) body: z.infer<typeof changePasswordDto>,
  ) {
    const tenantId = parseTenantId(req.headers['x-tenant-id'] as string | undefined);
    const principalId = req.principalId ?? req.userId;
    const result = await this.changePasswordHandler.handle(
      new ChangePasswordCommand(tenantId, principalId, body.currentPassword, body.newPassword, req.sessionId),
    );
    return { data: result };
  }

  // POST /auth/password/reset/request
  @Post('reset/request')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(IdempotencyInterceptor)
  async passwordResetRequest(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(passwordResetRequestDto)) body: z.infer<typeof passwordResetRequestDto>,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const result = await this.passwordResetRequestHandler.handle(
      new PasswordResetRequestCommand(tenantId, body.identity, body.identityType),
    );
    return { data: result };
  }

  // POST /auth/password/reset/confirm
  @Post('reset/confirm')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(IdempotencyInterceptor)
  async passwordResetConfirm(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(passwordResetConfirmDto)) body: z.infer<typeof passwordResetConfirmDto>,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const result = await this.passwordResetConfirmHandler.handle(
      new PasswordResetConfirmCommand(tenantId, body.resetToken, body.newPassword),
    );
    return { data: result };
  }
}
