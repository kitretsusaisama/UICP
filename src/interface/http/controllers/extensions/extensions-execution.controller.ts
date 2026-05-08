import { Controller, Post, Param, Req, Res, Headers, UseGuards, BadRequestException, PayloadTooLargeException } from '@nestjs/common';
import { ExtensionExecutorService } from '../../../../src/application/services/extensions/extension.executor';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { TenantGuard } from '../../guards/tenant.guard';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiHeader } from '@nestjs/swagger';
import * as getRawBody from 'raw-body';
import { Request, Response } from 'express';

@ApiTags('Extensions')
@Controller('v1/extensions')
export class ExtensionsExecutionController {
  constructor(private readonly executor: ExtensionExecutorService) {}

  @Post(':extensionKey/commands/:commandKey')
  @UseGuards(JwtAuthGuard, TenantGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Execute an extension command safely' })
  @ApiHeader({ name: 'x-signature', required: true, description: 'HMAC_SHA256 signature of payload+timestamp+nonce' })
  @ApiHeader({ name: 'x-timestamp', required: true, description: 'Unix timestamp of the request' })
  @ApiHeader({ name: 'x-nonce', required: true, description: 'Unique cryptographic nonce' })
  async executeCommand(
    @Req() req: any,
    @Res() res: Response,
    @Param('extensionKey') extensionKey: string,
    @Param('commandKey') commandKey: string,
    @Headers('x-signature') signature: string,
    @Headers('x-timestamp') timestampStr: string,
    @Headers('x-nonce') nonce: string
  ) {
    if (!signature || !timestampStr || !nonce) {
      throw new BadRequestException('Missing required cryptographic headers (x-signature, x-timestamp, x-nonce)');
    }

    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp)) {
       throw new BadRequestException('Invalid timestamp format');
    }

    // Must read raw body stream for exact HMAC hashing
    let rawBuffer: Buffer;
    try {
       rawBuffer = await getRawBody(req, {
         length: req.headers['content-length'],
         limit: '10kb',
       });
    } catch (err: any) {
       if (err.type === 'entity.too.large') {
           throw new PayloadTooLargeException('Command payload exceeds the 10KB size limit');
       }
       throw new BadRequestException('Invalid payload stream');
    }

    const rawPayloadStr = rawBuffer.toString('utf8');
    let payloadObject: any;
    try {
        payloadObject = JSON.parse(rawPayloadStr);
    } catch {
        throw new BadRequestException('Invalid JSON payload');
    }

    const ctx = {
      tenantId: req.user.tenantId,
      appId: req.user.appId || req.user.clientId || 'unknown_app',
      actorId: req.user.sub,
      requestId: req.headers['x-request-id'] || 'req_' + Date.now()
    };

    const result = await this.executor.executeCommand(
      ctx,
      extensionKey,
      commandKey,
      payloadObject,
      rawPayloadStr, // Pass raw exact string to hashing function
      signature,
      timestamp,
      nonce
    );

    return res.status(200).json(result);
  }
}
