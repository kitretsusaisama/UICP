import { Governance } from '../../../../src/infrastructure/governance/decorators/governance.decorator';
import { GovernanceGuard } from '../../../../src/infrastructure/governance/guards/governance.guard';
import { Controller, Post, Get, Put, Param, Body, UseGuards, Req, UseGuards } from '@nestjs/common';
import { WebhookService } from '../../../../application/services/platform/webhook.service';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { TenantGuard } from '../../guards/tenant.guard';

interface CreateWebhookDto {
  url: string;
  events: string[];
}

interface UpdateWebhookDto {
  url?: string;
  events?: string[];
  status?: 'active' | 'suspended';
}

@Controller('v1/apps/:appId/webhooks')
@UseGuards(JwtAuthGuard, TenantGuard)
export class WebhookController {
  constructor(private readonly webhookService: WebhookService) {}

  @Post()
  async registerWebhook(
    @Req() req: any,
    @Param('appId') appId: string,
    @Body() body: CreateWebhookDto
  ) {
    const tenantId = req.tenantId;
    const webhook = await this.webhookService.registerWebhook(
      tenantId,
      appId,
      body.url,
      body.events
    );
    return {
      success: true,
      data: webhook,
      meta: { version: 'v1' }
    };
  }

  @Get()
  async listWebhooks(@Req() req: any, @Param('appId') appId: string) {
    const tenantId = req.tenantId;
    const webhooks = await this.webhookService.listWebhooks(appId, tenantId);
    return {
      success: true,
      data: webhooks,
      meta: { version: 'v1' }
    };
  }

  @Get(':id')
  async getWebhook(@Req() req: any, @Param('id') id: string) {
    const tenantId = req.tenantId;
    const webhook = await this.webhookService.getWebhook(id, tenantId);
    return {
      success: true,
      data: webhook,
      meta: { version: 'v1' }
    };
  }

  @Put(':id')
  async updateWebhook(
    @Req() req: any,
    @Param('id') id: string,
    @Body() body: UpdateWebhookDto
  ) {
    const tenantId = req.tenantId;
    const webhook = await this.webhookService.updateWebhook(
      id,
      tenantId,
      body.url,
      body.events,
      body.status
    );
    return {
      success: true,
      data: webhook,
      meta: { version: 'v1' }
    };
  }
}
