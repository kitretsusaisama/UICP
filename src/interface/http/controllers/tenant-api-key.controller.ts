import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  Query,
  Req,
  BadRequestException,
} from '@nestjs/common';
import { ApiHeader, ApiTags, ApiOperation } from '@nestjs/swagger';
import { z } from 'zod';
import { TenantApiKeyService, CreateApiKeyRequest } from '../../../application/services/tenant-api-key.service';
import { ZodValidationPipe } from '../pipes/zod-validation.pipe';
import { TenantAwareRequest } from '../tenant/tenant-context';

const createApiKeyDto = z.object({
  name: z.string().min(1).max(100),
  scope: z.enum(['read', 'write', 'admin', 'fullaccess']).optional(),
  tier: z.enum(['free', 'standard', 'premium', 'enterprise']).optional(),
  ipAllowlist: z.array(z.string()).optional(),
  rateLimit: z.number().min(1).max(10000).optional(),
  allowedOrigins: z.array(z.string()).optional(),
  expiresInDays: z.number().min(1).max(365).optional(),
});

type CreateApiKeyDto = z.infer<typeof createApiKeyDto>;

const updateApiKeyDto = z.object({
  name: z.string().min(1).max(100).optional(),
  scope: z.enum(['read', 'write', 'admin', 'fullaccess']).optional(),
  tier: z.enum(['free', 'standard', 'premium', 'enterprise']).optional(),
  ipAllowlist: z.array(z.string()).optional(),
  rateLimit: z.number().min(1).max(10000).optional(),
  allowedOrigins: z.array(z.string()).optional(),
});

type UpdateApiKeyDto = z.infer<typeof updateApiKeyDto>;

@ApiTags('Tenant API Keys')
@ApiHeader({ name: 'x-tenant-id', required: true, description: 'Tenant UUID' })
@Controller('v1/tenant/api-keys')
export class TenantApiKeyController {
  constructor(private readonly apiKeyService: TenantApiKeyService) {}

  private getTenantId(req: TenantAwareRequest): string {
    if (!this.getTenantId(req)) throw new BadRequestException('Tenant ID is required');
    return this.getTenantId(req);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a new API key for the tenant' })
  async createApiKey(
    @Body(new ZodValidationPipe(createApiKeyDto)) body: CreateApiKeyDto,
    @Req() req: TenantAwareRequest,
  ) {
    const request: CreateApiKeyRequest = {
      tenantId: this.getTenantId(req),
      name: body.name,
      scope: body.scope,
      tier: body.tier,
      ipAllowlist: body.ipAllowlist,
      rateLimit: body.rateLimit,
      allowedOrigins: body.allowedOrigins,
      expiresInDays: body.expiresInDays,
    };

    const result = await this.apiKeyService.createApiKey(request);
    return { data: result };
  }

  @Get()
  @ApiOperation({ summary: 'List all API keys for the tenant' })
  async listApiKeys(@Req() req: TenantAwareRequest) {
    const keys = await this.apiKeyService.listApiKeys(this.getTenantId(req));
    return { data: keys.map(k => k.toResponse()) };
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a specific API key' })
  async getApiKey(@Param('id') id: string, @Req() req: TenantAwareRequest) {
    const key = await this.apiKeyService.getApiKey(id, this.getTenantId(req));
    return { data: key.toResponse() };
  }

  @Post(':id/rotate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Rotate API key (deprecate old, create new)' })
  async rotateApiKey(@Param('id') id: string, @Req() req: TenantAwareRequest) {
    const result = await this.apiKeyService.rotateApiKey(id, this.getTenantId(req));
    return { data: result };
  }

  @Post(':id/deprecate')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Deprecate API key (grace period before revocation)' })
  async deprecateApiKey(
    @Param('id') id: string,
    @Req() req: TenantAwareRequest,
    @Query('gracePeriodSeconds') gracePeriodSeconds?: string,
  ) {
    const gracePeriod = gracePeriodSeconds ? parseInt(gracePeriodSeconds, 10) : 3600;
    await this.apiKeyService.deprecateApiKey(id, this.getTenantId(req), gracePeriod);
  }

  @Post(':id/revoke')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke API key immediately' })
  async revokeApiKey(@Param('id') id: string, @Req() req: TenantAwareRequest) {
    await this.apiKeyService.revokeApiKey(id, this.getTenantId(req));
  }

  @Put(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Update API key settings' })
  async updateApiKey(
    @Param('id') id: string,
    @Body(new ZodValidationPipe(updateApiKeyDto)) body: UpdateApiKeyDto,
    @Req() req: TenantAwareRequest,
  ) {
    const key = await this.apiKeyService.updateApiKey(id, this.getTenantId(req), body);
    return { data: key.toResponse() };
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete deprecated or revoked API key' })
  async deleteApiKey(@Param('id') id: string, @Req() req: TenantAwareRequest) {
    await this.apiKeyService.deleteApiKey(id, this.getTenantId(req));
  }
}