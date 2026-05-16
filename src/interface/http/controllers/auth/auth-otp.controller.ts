import { QueueBackpressureGuard } from '../../guards/queue-backpressure.guard';
import {
  BadRequestException,
  Body,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Inject,
  Logger,
  Post,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { ApiHeader, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';

import { VerifyOtpCommand } from '@application/commands/verify-otp/verify-otp.command';
import { VerifyOtpHandler } from '@application/commands/verify-otp/verify-otp.handler';
import { OtpDispatchPayload } from '@application/contracts/otp-dispatch.contract';
import { OtpService } from '@application/services/otp.service';
import { IQueuePort } from '@application/ports/driven/i-queue.port';
import { INJECTION_TOKENS } from '@application/ports/injection-tokens';
import { IdempotencyInterceptor } from '../../interceptors/idempotency.interceptor';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { otpSendDto, otpVerifyDto } from '../../dtos';
import { parseTenantId } from '../../tenant/tenant-context';

/**
 * Auth OTP Controller
 * Handles: otp/send, otp/verify
 */
@ApiTags('Auth - OTP')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/auth/otp')
@UseGuards(QueueBackpressureGuard)
export class AuthOtpController {
  private readonly logger = new Logger(AuthOtpController.name);

  constructor(
    private readonly verifyOtpHandler: VerifyOtpHandler,
    private readonly otpService: OtpService,
    @Inject(INJECTION_TOKENS.QUEUE_PORT)
    private readonly queue: IQueuePort,
  ) {}

  // POST /auth/otp/send
  @Post('send')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(IdempotencyInterceptor)
  async sendOtp(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(otpSendDto)) body: z.infer<typeof otpSendDto>,
  ) {
    parseTenantId(rawTenantId);
    const recipient = body.recipient ?? body.email ?? body.phone;
    if (!recipient) {
      throw new BadRequestException({
        error: { code: 'MISSING_OTP_RECIPIENT', message: 'recipient, email, or phone is required' },
      });
    }

    const channel = ((body.channel ?? (recipient.includes('@') ? 'EMAIL' : 'SMS')) as string).toUpperCase() as
      | 'EMAIL'
      | 'SMS';
    const code = this.otpService.generate();
    await this.otpService.store(body.userId, body.purpose, code);
    const payload: OtpDispatchPayload = {
      userId: body.userId,
      tenantId: rawTenantId,
      recipient,
      channel,
      purpose: body.purpose,
      code,
      tenantName: body.tenantName,
    };
    await this.queue.enqueue('otp-send', payload);
    this.logger.log({ userId: body.userId, purpose: body.purpose, channel }, 'OTP dispatched');
    return { data: { sent: true, channel: channel.toLowerCase() } };
  }

  // POST /auth/otp/verify
  @Post('verify')
  @HttpCode(HttpStatus.OK)
  async verifyOtp(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(otpVerifyDto)) body: z.infer<typeof otpVerifyDto>,
  ) {
    const tenantId = parseTenantId(rawTenantId);
    const result = await this.verifyOtpHandler.handle(
      new VerifyOtpCommand(tenantId, body.userId, body.code, body.purpose, body.identityId, body.sessionId),
    );
    return { data: result };
  }
}
