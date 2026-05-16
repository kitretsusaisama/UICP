import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { AppSecretService } from '../../../../application/services/platform/app-secret.service';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { createSecretDto } from '../../dtos/platform/app-secret.dto';

@Controller('v1/platform/apps/:appId/secrets')
export class AppSecretController {
  constructor(private readonly secrets: AppSecretService) {}

  @Get()
  async list(@Param('appId') appId: string) {
    return { data: { appId, secrets: [] } };
  }

  @Post()
  async create(
    @Param('appId') appId: string,
    @Body(new ZodValidationPipe(createSecretDto)) body: z.infer<typeof createSecretDto>,
  ) {
    return { data: { appId, accepted: true, request: body } };
  }
}
