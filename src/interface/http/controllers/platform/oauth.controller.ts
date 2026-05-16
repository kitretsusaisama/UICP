import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { z } from 'zod';
import { OAuthService } from '../../../../application/services/platform/oauth.service';
import { ZodValidationPipe } from '../../pipes/zod-validation.pipe';
import { tokenRequestDto } from '../../dtos/platform/oauth.dto';

@Controller('v1/platform/oauth')
export class OAuthController {
  constructor(private readonly oauth: OAuthService) {}

  @Get('authorize')
  async authorize(@Query() query: Record<string, string>) {
    return { data: { authorize: true, query } };
  }

  @Post('token')
  async token(
    @Body(new ZodValidationPipe(tokenRequestDto)) body: z.infer<typeof tokenRequestDto>,
  ) {
    return { data: { accepted: true, tokenRequest: body } };
  }
}
