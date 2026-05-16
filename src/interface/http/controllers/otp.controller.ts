import {
  Controller,
  Get,
  Post,
  Body,
  Headers,
  HttpCode,
  HttpStatus,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import { ApiHeader, ApiTags } from '@nestjs/swagger';
import { UniversalOtpKernel } from '../../../infrastructure/otp/kernel/universal-otp-kernel';
import { ZodValidationPipe } from '../pipes/zod-validation.pipe';
import {
  widgetSendDto,
  WidgetSendDto,
  widgetRetryDto,
  WidgetRetryDto,
  widgetVerifyV2Dto,
  WidgetVerifyV2Dto,
} from '../dtos';

function parseTenantId(raw: string | undefined): string {
  if (!raw) {
    throw new BadRequestException({
      error: { code: 'MISSING_TENANT_ID', message: 'X-Tenant-ID header is required' },
    });
  }
  const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRe.test(raw)) {
    throw new BadRequestException({
      error: { code: 'INVALID_TENANT_ID', message: `Invalid tenant ID: ${raw}` },
    });
  }
  return raw;
}

@ApiTags('OTP Widget')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/auth/otp/widget')
export class OtpWidgetController {
  private readonly logger = new Logger(OtpWidgetController.name);

  constructor(private readonly otpKernel: UniversalOtpKernel) { }

  @Get('config')
  @HttpCode(HttpStatus.OK)
  async getWidgetConfig(
    @Headers('x-tenant-id') rawTenantId: string,
  ) {
    const tenantId = parseTenantId(rawTenantId);

    const config = await this.otpKernel.getWidgetConfig(tenantId);

    this.logger.debug({ tenantId }, 'Widget config retrieved');
    return { data: config };
  }

  @Post('send')
  @HttpCode(HttpStatus.OK)
  async sendOtp(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(widgetSendDto)) body: WidgetSendDto,
  ) {
    const tenantId = parseTenantId(rawTenantId);

    const challenge = await this.otpKernel.sendOtp({
      tenantId,
      identity: body.identity,
      channel: body.channel ?? 'SMS',
      purpose: body.purpose ?? 'IDENTITY_VERIFICATION',
      deviceFingerprint: body.deviceFingerprint,
      ipAddress: body.ipAddress,
    });

    this.logger.debug({
      tenantId,
      identity: body.identity,
      channel: body.channel,
      challengeId: challenge.id,
    }, 'OTP sent via widget');

    return { data: challenge };
  }

  @Post('verify')
  @HttpCode(HttpStatus.OK)
  async verifyOtp(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(widgetVerifyV2Dto)) body: WidgetVerifyV2Dto,
  ) {
    const tenantId = parseTenantId(rawTenantId);

    if (!body.providerToken && !body.code) {
      throw new BadRequestException({
        error: {
          code: 'MISSING_VERIFICATION',
          message: 'Either providerToken or code is required',
        },
      });
    }

    const result = await this.otpKernel.verifyOtp({
      tenantId,
      challengeId: body.challengeId ?? '',
      providerToken: body.providerToken,
      code: body.code,
      deviceFingerprint: body.deviceFingerprint,
      ipAddress: body.ipAddress,
    });

    this.logger.debug({
      tenantId,
      identity: body.identity,
      verified: result.verified,
    }, 'OTP verified via widget');

    return { data: result };
  }

  @Post('retry')
  @HttpCode(HttpStatus.OK)
  async retryOtp(
    @Headers('x-tenant-id') rawTenantId: string,
    @Body(new ZodValidationPipe(widgetRetryDto)) body: WidgetRetryDto,
  ) {
    const tenantId = parseTenantId(rawTenantId);

    const challenge = await this.otpKernel.retryOtp({
      tenantId,
      challengeId: body.challengeId,
      newChannel: body.newChannel,
    });

    this.logger.debug({
      tenantId,
      challengeId: body.challengeId,
      newChannel: body.newChannel,
    }, 'OTP retried via widget');

    return { data: challenge };
  }

  @Get('channels')
  @HttpCode(HttpStatus.OK)
  async getAvailableChannels(
    @Headers('x-tenant-id') rawTenantId: string,
  ) {
    parseTenantId(rawTenantId);

    return {
      data: {
        channels: ['SMS', 'WHATSAPP', 'VOICE', 'EMAIL'],
        default: 'SMS',
        fallbackOrder: ['WHATSAPP', 'SMS', 'EMAIL'],
      },
    };
  }
}