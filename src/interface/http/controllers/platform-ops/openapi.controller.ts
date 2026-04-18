import { Controller, Get, Res, Inject } from '@nestjs/common';
import { Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { ApiTags, ApiOperation } from '@nestjs/swagger';

@ApiTags('Operations')
@Controller('v1/platform')
export class OpenApiController {

  @Get('openapi')
  @ApiOperation({ summary: 'Retrieve the static, versioned OpenAPI snapshot' })
  getOpenApiSnapshot(@Res() res: Response) {
    const filePath = path.join(process.cwd(), 'swagger-spec.json');
    if (fs.existsSync(filePath)) {
       res.sendFile(filePath);
    } else {
       // Fallback for development if the snapshot isn't built yet
       res.redirect('/api-docs-json');
    }
  }

  @Get('sdk-descriptor')
  @ApiOperation({ summary: 'Retrieve supported SDKs and Auth Types' })
  getSdkDescriptor() {
    return {
      languages: ['ts', 'java', 'go', 'python'],
      auth: ['oauth2', 'apiKey', 'bearer'],
      baseUrl: process.env.BASE_URL || 'https://api.uicp.com',
      version: process.env.VERSION || '0.0.0-dev'
    };
  }
}
