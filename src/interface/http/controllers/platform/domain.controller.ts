import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { z } from 'zod';
import { DomainService } from '../../../../application/services/platform/domain.service';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { createDomainDto } from '../../dtos/platform/domain.dto';

@Controller('v1/platform/domains')
export class DomainController {
  constructor(private readonly domains: DomainService) {}

  @Get(':domain')
  async get(@Param('domain') domain: string) {
    return { data: { domain } };
  }

  @Post()
  async create(
    @Body(new ZodValidationPipe(createDomainDto)) body: z.infer<typeof createDomainDto>,
  ) {
    return { data: { accepted: true, domain: body } };
  }
}
