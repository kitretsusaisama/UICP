import { Controller, Get, UseGuards, Header } from '@nestjs/common';
import { MetricsService } from '../../../../src/application/services/platform-ops/metrics.service';
import { MetricsAuthGuard } from '../../guards/metrics-auth.guard';
import { ApiTags, ApiOperation } from '@nestjs/swagger';

@ApiTags('Operations')
@Controller('v1/metrics')
export class MetricsController {
  constructor(private readonly metricsService: MetricsService) {}

  @Get()
  @UseGuards(MetricsAuthGuard)
  @Header('Content-Type', 'text/plain')
  @ApiOperation({ summary: 'Prometheus metrics endpoint (Secured via IP+Token)' })
  async getMetrics(): Promise<string> {
    return this.metricsService.getMetrics();
  }
}
