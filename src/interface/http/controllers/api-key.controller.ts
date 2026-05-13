import {
  Controller,
  Get,
  Post,
  Delete,
  Body,
  Param,
  Req,
  HttpCode,
  HttpStatus,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { z } from 'zod';
import { ApiKeyService } from '../../../application/services/api-key.service';
import { ApiKeyScope } from '../../../domain/entities/api-key.entity';
import { TenantAwareRequest } from '../tenant/tenant-context';
import { ZodValidationPipe } from '../pipes/zod-validation.pipe';

const createApiKeyDto = z.object({
  name: z.string().max(100).optional(),
  scopes: z.enum(['read', 'write', 'admin']).array().optional(),
  ipAllowlist: z.string().array().optional(),
  rateLimit: z.number().min(1).max(10000).optional(),
  expiresInDays: z.number().min(1).max(365).optional(),
  env: z.enum(['live', 'dev']).optional(),
});

type CreateApiKeyDto = z.infer<typeof createApiKeyDto>;

@ApiTags('API Keys')
@Controller('v1/api-keys')
export class ApiKeyController {
  constructor(private readonly apiKeyService: ApiKeyService) {}

  private getTenantId(req: TenantAwareRequest): string {
    if (!req.tenantId) throw new BadRequestException('Tenant ID required');
    return req.tenantId;
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create new API key pair' })
  async create(
    @Body(new ZodValidationPipe(createApiKeyDto)) body: CreateApiKeyDto,
    @Req() req: TenantAwareRequest,
  ) {
    const result = await this.apiKeyService.create({
      tenantId: this.getTenantId(req),
      name: body.name,
      scopes: body.scopes as ApiKeyScope[],
      ipAllowlist: body.ipAllowlist,
      rateLimit: body.rateLimit,
      expiresInDays: body.expiresInDays,
      env: body.env as any,
    });
    return {
      publishableKey: result.publishableKey,
      secretKey: result.secretKey,
      key: result.apiKey.toResponse(),
    };
  }

  @Get()
  @ApiOperation({ summary: 'List all API keys for tenant' })
  async list(@Req() req: TenantAwareRequest) {
    const keys = await this.apiKeyService.listByTenant(this.getTenantId(req));
    return { data: keys.map(k => k.toResponse()) };
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get API key details' })
  async get(@Param('id') id: string, @Req() req: TenantAwareRequest) {
    const key = await this.apiKeyService.getByUlid(id);
    if (!key || key.tenantId !== this.getTenantId(req)) {
      throw new BadRequestException('API key not found');
    }
    return { data: key.toResponse() };
  }

  @Post(':id/rotate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Rotate API key' })
  async rotate(@Param('id') id: string, @Req() req: TenantAwareRequest) {
    const result = await this.apiKeyService.rotate(id, this.getTenantId(req));
    return {
      publishableKey: result.publishableKey,
      secretKey: result.secretKey,
      key: result.apiKey.toResponse(),
    };
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke API key' })
  async revoke(@Param('id') id: string, @Req() req: TenantAwareRequest) {
    await this.apiKeyService.revoke(id, this.getTenantId(req));
  }
}
