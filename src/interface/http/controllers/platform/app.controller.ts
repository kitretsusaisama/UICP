import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { AppService } from '../../../../application/services/platform/app.service';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { createAppDto } from '../../dtos/platform/app.dto';

@Controller('v1/platform/apps')
export class AppController {
  constructor(private readonly apps: AppService) {}

  @Get(':id')
  async get(@Param('id') id: string) {
    return { data: { id } };
  }

  @Post()
  async create(
    @Body(new ZodValidationPipe(createAppDto)) body: z.infer<typeof createAppDto>,
  ) {
    return { data: { accepted: true, app: body } };
  }
}
