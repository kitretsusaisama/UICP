import { Controller, Get, Post, Delete, Param, Query, UseGuards, Req, Res, BadRequestException } from '@nestjs/common';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard, Roles } from '../guards/roles.guard';
import { TenantGuard } from '../guards/tenant.guard';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { QueueAdapter } from '../../../../src/infrastructure/queue/bullmq-queue.adapter';
import { Inject } from '@nestjs/common';
import { ulid } from 'ulid';
import { CACHE_ADAPTER } from '../../../../src/domain/repositories/cache.repository.interface';
import { CacheAdapter } from '../../../../src/infrastructure/cache/redis-cache.adapter';
import { AuditLogWriter } from '../../../../src/application/services/audit-log.writer';

@ApiTags('Admin')
@Controller('v1/admin')
@UseGuards(JwtAuthGuard, TenantGuard)
@ApiBearerAuth()
export class AdminController {
  constructor(
    @Inject('QUEUE_ADAPTER') private readonly queue: QueueAdapter,
    @Inject(CACHE_ADAPTER) private readonly cache: CacheAdapter,
    private readonly auditWriter: AuditLogWriter
  ) {}

  @Post('tenant')
  @UseGuards(RolesGuard)
  @Roles('super_admin')
  @ApiOperation({ summary: 'Provision new tenant globally' })
  async provisionTenant() {
     // ... mock ...
     return { success: true };
  }

  @Delete('users/:id/devices/:deviceId')
  @UseGuards(RolesGuard)
  @Roles('user:write', 'super_admin')
  @ApiOperation({ summary: 'Remove a specific device/session from a user safely' })
  async removeDevice(
    @Req() req: any,
    @Param('id') userId: string,
    @Param('deviceId') deviceId: string
  ) {
     const tenantId = req.user.tenantId;

     // Remove device from Redis trusted set
     await this.cache.srem(`trusted-devices:${tenantId}:${userId}`, deviceId);

     // Also invalidate matching sessions physically mapped in Redis if required
     // (SessionService typically maps active sessions, for compliance we ensure the trust removal forces an MFA step up next time)

     this.auditWriter.writeLog({
        auditId: ulid(),
        tenantId,
        actorId: req.user.sub,
        event: 'DEVICE_REVOKED',
        timestamp: Date.now(),
        metadata: JSON.stringify({ targetUserId: userId, deviceId })
     });

     return {
       success: true,
       data: { removed: true },
       meta: { requestId: req.headers['x-request-id'] || ulid(), timestamp: Math.floor(Date.now()/1000) }
     };
  }
}
