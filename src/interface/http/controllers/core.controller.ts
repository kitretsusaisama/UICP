import { Controller, Get, UseGuards, UseInterceptors, Req } from '@nestjs/common';
import { IamController } from './iam.controller';
import { InternalServiceGuard } from '../guards/internal-service.guard';
import { DeprecatedApiInterceptor } from '../interceptors/deprecated-api.interceptor';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';

/**
 * ⚠️ DEPRECATED NAMESPACE ⚠️
 * /v1/core/* is strictly mapped to /v1/users/me/*
 * No new endpoints or distinct business logic should be added here.
 * Only internal services (via InternalServiceGuard) can invoke these paths.
 */
@ApiTags('Core (Deprecated)')
@Controller('v1/core')
@UseGuards(InternalServiceGuard)
@UseInterceptors(DeprecatedApiInterceptor)
@ApiBearerAuth()
export class CoreController {
  constructor(private readonly iamController: IamController) {}

  @Get('sessions')
  @ApiOperation({ summary: '[DEPRECATED] Internal alias for /users/me/sessions' })
  async getSessions(@Req() req: any) {
     return this.iamController.getSessions(req);
  }

  @Get('devices')
  @ApiOperation({ summary: '[DEPRECATED] Internal alias for /users/me/devices' })
  async getDevices(@Req() req: any) {
     return this.iamController.getDevices(req);
  }

  @Get('me')
  @ApiOperation({ summary: '[DEPRECATED] Internal alias for /users/me' })
  async getMe(@Req() req: any) {
     return this.iamController.getProfile(req);
  }
}
