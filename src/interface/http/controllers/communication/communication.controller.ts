import { Body, Controller, Get, Headers, Param, Post, Req } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { z } from 'zod';
import { CommunicationRuntime } from '../../../../application/communication/communication-runtime.service';
import { EmailRuntime } from '../../../../application/communication/email-runtime.service';
import { ProviderHealthRuntime } from '../../../../application/communication/provider-health-runtime.service';
import { WebhookRuntime } from '../../../../application/communication/webhook-runtime.service';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import {
  sendOtpDto,
  retryOtpDto,
  verifyOtpDto,
  commWidgetVerifyDto,
  sendEmailDto,
  SendEmailDto,
  createTemplateDto,
  webhookPayloadDto,
  sendEmailBatchDto,
  channelSchema,
  purposeSchema,
} from '../../dtos/communication/communication.dto';

function tenantId(headersTenantId: string | undefined): string {
  return headersTenantId ?? '00000000-0000-4000-8000-000000000000';
}

@ApiTags('Communication Runtime')
@Controller()
export class CommunicationController {
  constructor(
    private readonly communication: CommunicationRuntime,
    private readonly email: EmailRuntime,
    private readonly health: ProviderHealthRuntime,
    private readonly webhooks: WebhookRuntime,
  ) {}

  @Post('v1/auth/otp/runtime/send')
  async sendOtp(
    @Headers('x-tenant-id') rawTenantId: string | undefined,
    @Body(new ZodValidationPipe(sendOtpDto)) body: z.infer<typeof sendOtpDto>,
    @Req() req: { headers: Record<string, string | string[] | undefined> },
  ) {
    const result = await this.communication.sendOtp({
      tenantId: tenantId(rawTenantId),
      traceId: String(req.headers['x-request-id'] ?? ''),
      ...body,
    });
    return { data: result };
  }

  @Post('v1/auth/otp/retry')
  async retryOtp(
    @Headers('x-tenant-id') rawTenantId: string | undefined,
    @Body(new ZodValidationPipe(retryOtpDto)) body: z.infer<typeof retryOtpDto>,
  ) {
    return {
      data: await this.communication.retryOtp({
        tenantId: tenantId(rawTenantId),
        ...body,
      }),
    };
  }

  @Post('v1/auth/otp/runtime/verify')
  async verifyOtp(
    @Headers('x-tenant-id') rawTenantId: string | undefined,
    @Body(new ZodValidationPipe(verifyOtpDto)) body: z.infer<typeof verifyOtpDto>,
  ) {
    return {
      data: await this.communication.verifyOtp({
        tenantId: tenantId(rawTenantId),
        ...body,
      }),
    };
  }

  @Post('v1/auth/otp/widget/verify-token')
  async verifyWidgetToken(
    @Headers('x-tenant-id') rawTenantId: string | undefined,
    @Body(new ZodValidationPipe(commWidgetVerifyDto)) body: z.infer<typeof commWidgetVerifyDto>,
  ) {
    return {
      data: await this.communication.verifyProviderToken({
        tenantId: tenantId(rawTenantId),
        ...body,
      }),
    };
  }

  @Get('v1/auth/otp/challenges/:challengeId')
  async getChallenge(@Headers('x-tenant-id') rawTenantId: string | undefined, @Param('challengeId') challengeId: string) {
    return {
      data: {
        tenantId: tenantId(rawTenantId),
        challengeId,
        status: 'opaque',
      },
    };
  }

  @Post('v1/communication/email/send')
  async sendEmail(
    @Headers('x-tenant-id') rawTenantId: string | undefined,
    @Body(new ZodValidationPipe(sendEmailDto)) body: z.infer<typeof sendEmailDto>,
  ) {
    return {
      data: await this.email.send({
        tenantId: tenantId(rawTenantId),
        ...body,
      }),
    };
  }

  @Post('v1/communication/email/batch')
  async sendEmailBatch(
    @Headers('x-tenant-id') rawTenantId: string | undefined,
    @Body(new ZodValidationPipe(sendEmailBatchDto)) body: z.infer<typeof sendEmailBatchDto>,
  ) {
    const results = await Promise.all(body.items.map((item: SendEmailDto) => this.email.send({ tenantId: tenantId(rawTenantId), ...item })));
    return { data: { queued: results.length, results } };
  }

  @Get('v1/communication/templates')
  async listTemplates() {
    return { data: [] };
  }

  @Post('v1/communication/templates')
  async createTemplate(
    @Body(new ZodValidationPipe(createTemplateDto)) body: z.infer<typeof createTemplateDto>,
  ) {
    return { data: { accepted: true, template: body } };
  }

  @Post('v1/communication/webhooks/:provider')
  async processWebhook(
    @Param('provider') provider: string,
    @Body(new ZodValidationPipe(webhookPayloadDto)) body: z.infer<typeof webhookPayloadDto>,
    @Req() req: { headers: Record<string, string | string[] | undefined> },
  ) {
    const headers = Object.fromEntries(
      Object.entries(req.headers).map(([key, value]) => [key, Array.isArray(value) ? value.join(',') : String(value ?? '')]),
    );
    return { data: this.webhooks.process(provider, body, headers) };
  }

  @Get('v1/communication/deliveries/:lineageId')
  async getDelivery(@Headers('x-tenant-id') rawTenantId: string | undefined, @Param('lineageId') lineageId: string) {
    return {
      data: {
        tenantId: tenantId(rawTenantId),
        lineageId,
        status: 'queued',
      },
    };
  }

  @Get('v1/providers/health')
  async providerHealth(@Headers('x-tenant-id') rawTenantId: string | undefined) {
    return { data: this.health.list(tenantId(rawTenantId)) };
  }
}
