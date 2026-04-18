import { Controller, Get } from '@nestjs/common';
import { HealthService } from '../../../../src/application/services/platform-ops/health.service';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('Operations')
@Controller('v1/health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get('live')
  @ApiOperation({ summary: 'Liveness probe (fast, lightweight)' })
  @ApiResponse({ status: 200, description: 'Service is alive' })
  getLiveness() {
    return this.healthService.getLiveness();
  }

  @Get('ready')
  @ApiOperation({ summary: 'Readiness probe (deep dependency check)' })
  @ApiResponse({ status: 200, description: 'Service is ready to handle traffic' })
  @ApiResponse({ status: 503, description: 'Service is not ready (Redis or MySQL down)' })
  async getReadiness() {
    return this.healthService.getReadiness();
  }
}
