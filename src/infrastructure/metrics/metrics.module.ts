import { Module } from '@nestjs/common';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';
import { PromClientMetricsAdapter } from './prom-client.metrics.adapter';
import { MetricsController } from './metrics.controller';

/**
 * Provides the Prometheus metrics adapter and exposes the /metrics scrape endpoint.
 *
 * Exports METRICS_PORT so other modules (command handlers, workers) can inject it.
 *
 * Implements: Req 15.3, Req 16.4
 */
@Module({
  controllers: [MetricsController],
  providers: [
    {
      provide: INJECTION_TOKENS.METRICS_PORT,
      useClass: PromClientMetricsAdapter,
    },
  ],
  exports: [INJECTION_TOKENS.METRICS_PORT],
})
export class MetricsModule {}
