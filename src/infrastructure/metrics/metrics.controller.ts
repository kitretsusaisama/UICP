import { Controller, Get, Inject, Res } from '@nestjs/common';
import { Response } from 'express';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { IMetricsPort } from '../../application/ports/driven/i-metrics.port';
import { PromClientMetricsAdapter } from './prom-client.metrics.adapter';

/**
 * Exposes the Prometheus scrape endpoint at GET /metrics.
 *
 * Returns metrics in Prometheus text format with the correct Content-Type header.
 * This endpoint is unauthenticated — it should be protected at the network level
 * (e.g. only accessible from within the cluster / scrape network).
 *
 * Implements: Req 15.3, Req 16.4
 */
@Controller()
export class MetricsController {
  constructor(
    @Inject(INJECTION_TOKENS.METRICS_PORT)
    private readonly metricsAdapter: IMetricsPort & Pick<PromClientMetricsAdapter, 'getMetrics' | 'getContentType'>,
  ) {}

  @Get('metrics')
  async getMetrics(@Res() res: Response): Promise<void> {
    const body = await this.metricsAdapter.getMetrics();
    const contentType = this.metricsAdapter.getContentType();
    res.setHeader('Content-Type', contentType);
    res.end(body);
  }
}
