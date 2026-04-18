import { Controller, Get, UseGuards } from '@nestjs/common';
import { StatusService } from '../../../../src/application/services/platform-ops/status.service';
import { JwtAuthGuard } from '../../guards/jwt-auth.guard';
import { RolesGuard, Roles } from '../../guards/roles.guard';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';

@ApiTags('Operations')
@Controller('v1/status')
export class StatusController {
  constructor(private readonly statusService: StatusService) {}

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('super_admin')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Operational status summary (Requires super_admin)' })
  async getStatus() {
    return this.statusService.getOperationalStatus();
  }
}
