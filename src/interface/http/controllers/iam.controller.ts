import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { TenantGuard } from '../guards/tenant.guard';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { SessionService } from '../../../../src/application/services/session.service';

@ApiTags('Users')
@Controller('v1/users/me')
@UseGuards(JwtAuthGuard, TenantGuard)
@ApiBearerAuth()
export class IamController {
  constructor(private readonly sessionService: SessionService) {}

  @Get()
  @ApiOperation({ summary: 'Get current user profile (Canonical)' })
  async getProfile(@Req() req: any) {
    return {
      success: true,
      data: {
        id: req.user.sub,
        tenantId: req.user.tenantId,
        roles: req.user.roles || []
      }
    };
  }

  @Get('sessions')
  @ApiOperation({ summary: 'Get all active sessions (Canonical)' })
  async getSessions(@Req() req: any) {
    // In a real implementation this delegates to sessionService
    return {
      success: true,
      data: { sessions: [] }
    };
  }

  @Get('devices')
  @ApiOperation({ summary: 'Get all active devices (Canonical)' })
  async getDevices(@Req() req: any) {
    return {
       success: true,
       data: { devices: [] }
    };
  }
}
