import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { WebhookService } from '../../../../application/services/platform/webhook.service';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { createWebhookDto } from '../../dtos/platform/webhook.dto';

@Controller('v1/platform/webhooks')
export class WebhookController {
  constructor(private readonly webhooks: WebhookService) {}

  @Get(':id')
  async get(@Param('id') id: string) {
    return { data: { id } };
  }

  @Post()
  async create(
    @Body(new ZodValidationPipe(createWebhookDto)) body: z.infer<typeof createWebhookDto>,
  ) {
    return { data: { accepted: true, webhook: body } };
  }
}
