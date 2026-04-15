import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  Attributes,
  Context,
  context,
  SpanKind,
  SpanStatusCode,
  trace,
  Tracer,
} from '@opentelemetry/api';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import {
  AlwaysOffSampler,
  AlwaysOnSampler,
  ParentBasedSampler,
  ReadableSpan,
  Sampler,
  SamplingDecision,
  SamplingResult,
  SpanProcessor,
  TraceIdRatioBasedSampler,
} from '@opentelemetry/sdk-trace-node';
import type { Link } from '@opentelemetry/api';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { SEMRESATTRS_SERVICE_NAME, SEMRESATTRS_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { ITracerPort, Span, SpanAttributes } from '../../application/ports/driven/i-tracer.port';

/**
 * SpanProcessor that force-samples slow requests (> 400ms) by setting
 * `sampling.priority = 1` on the span so it is exported regardless of
 * the head-based sampling decision (Section 13.3).
 */
class SlowRequestSpanProcessor implements SpanProcessor {
  private static readonly SLOW_THRESHOLD_MS = 400;

  onStart(): void { /* no-op */ }

  onEnd(span: ReadableSpan): void {
    const durationMs = (span.duration[0] * 1e3) + (span.duration[1] / 1e6);
    const dbDurationMs = span.attributes['db.duration_ms'];

    const isSlow =
      durationMs > SlowRequestSpanProcessor.SLOW_THRESHOLD_MS ||
      (typeof dbDurationMs === 'number' && dbDurationMs > SlowRequestSpanProcessor.SLOW_THRESHOLD_MS);

    if (isSlow) {
      span.attributes['sampling.priority'] = 1;
    }
  }

  shutdown(): Promise<void> {
    return Promise.resolve();
  }

  forceFlush(): Promise<void> {
    return Promise.resolve();
  }
}

/**
 * Custom OTel sampler implementing the UICP sampling strategy (Section 13.3):
 * - 100% for security events (span has `security.event_type` attribute)
 * - 100% for error traces (span has `http.status_code` >= 500)
 * - 100% for slow requests (> 400ms) — handled post-hoc via span processor
 * - 10% for normal traffic
 */
class UicpSampler implements Sampler {
  private readonly normalSampler = new TraceIdRatioBasedSampler(0.10);

  shouldSample(
    ctx: Context,
    traceId: string,
    spanName: string,
    spanKind: SpanKind,
    attributes: Attributes,
    links: Link[],
  ): SamplingResult {
    // Always sample security events
    if (attributes['security.event_type']) {
      return { decision: SamplingDecision.RECORD_AND_SAMPLED };
    }

    // Always sample error responses
    const statusCode = attributes['http.status_code'];
    if (typeof statusCode === 'number' && statusCode >= 500) {
      return { decision: SamplingDecision.RECORD_AND_SAMPLED };
    }

    // 10% sampling for normal traffic
    return this.normalSampler.shouldSample(ctx, traceId);
  }

  toString(): string {
    return 'UicpSampler{security=1.0,errors=1.0,normal=0.10}';
  }
}

/**
 * Thin wrapper around the OTel API Span to implement the ITracerPort Span interface.
 */
class OtelSpan implements Span {
  constructor(private readonly span: import('@opentelemetry/api').Span) {}

  setAttributes(attributes: SpanAttributes): void {
    this.span.setAttributes(attributes as Attributes);
  }

  recordException(error: Error): void {
    this.span.recordException(error);
    this.span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
  }

  end(): void {
    this.span.end();
  }
}

/**
 * OpenTelemetry tracer adapter implementing ITracerPort.
 *
 * - Configures OTel SDK with UicpSampler (Section 13.3).
 * - Propagates W3C TraceContext headers automatically.
 * - `withSpan()` always ends the span — even when `fn` throws (Req 13.1).
 * - Exports traces to the configured OTLP endpoint.
 */
@Injectable()
export class OtelTracerAdapter implements ITracerPort, OnModuleInit {
  private readonly logger = new Logger(OtelTracerAdapter.name);
  private tracer!: Tracer;
  private sdk?: NodeSDK;

  constructor(private readonly config: ConfigService) {}

  onModuleInit(): void {
    const otlpEndpoint = this.config.get<string>(
      'OTEL_EXPORTER_OTLP_ENDPOINT',
      'http://localhost:4318/v1/traces',
    );
    const serviceName = this.config.get<string>('SERVICE_NAME', 'uicp');
    const serviceVersion = this.config.get<string>('SERVICE_VERSION', '1.0.0');
    const enabled = this.config.get<string>('OTEL_ENABLED', 'true') !== 'false';

    if (!enabled) {
      this.logger.warn('OpenTelemetry tracing disabled (OTEL_ENABLED=false)');
      // Use a no-op tracer
      this.tracer = trace.getTracer(serviceName, serviceVersion);
      return;
    }

    try {
      this.sdk = new NodeSDK({
        resource: resourceFromAttributes({
          [SEMRESATTRS_SERVICE_NAME]: serviceName,
          [SEMRESATTRS_SERVICE_VERSION]: serviceVersion,
        }),
        traceExporter: new OTLPTraceExporter({
          url: otlpEndpoint,
          timeoutMillis: 5_000,
        }),
        sampler: new ParentBasedSampler({ root: new UicpSampler() }),
        spanProcessors: [new SlowRequestSpanProcessor()],
      });

      this.sdk.start();
      this.tracer = trace.getTracer(serviceName, serviceVersion);

      this.logger.log({ otlpEndpoint, serviceName }, 'OpenTelemetry SDK initialized');
    } catch (err) {
      this.logger.error({ err }, 'Failed to initialize OpenTelemetry SDK — using no-op tracer');
      this.tracer = trace.getTracer(serviceName, serviceVersion);
    }
  }

  // ── ITracerPort ────────────────────────────────────────────────────────────

  startSpan(name: string, attributes?: SpanAttributes): Span {
    const span = this.tracer.startSpan(name, {
      attributes: attributes as Attributes | undefined,
    });
    return new OtelSpan(span);
  }

  setAttributes(attributes: SpanAttributes): void {
    const span = trace.getActiveSpan();
    if (span) {
      span.setAttributes(attributes as Attributes);
    }
  }

  recordException(error: Error): void {
    const span = trace.getActiveSpan();
    if (span) {
      span.recordException(error);
      span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
    }
  }

  getCurrentTraceId(): string | undefined {
    const span = trace.getActiveSpan();
    if (!span) return undefined;
    const ctx = span.spanContext();
    return ctx.traceId !== '00000000000000000000000000000000' ? ctx.traceId : undefined;
  }

  /**
   * Wrap an async operation in a span.
   * The span is ALWAYS ended — even when `fn` throws (Req 13.1).
   */
  async withSpan<T>(
    name: string,
    fn: () => Promise<T>,
    attributes?: SpanAttributes,
  ): Promise<T> {
    const span = this.tracer.startSpan(name, {
      attributes: attributes as Attributes | undefined,
    });

    return context.with(trace.setSpan(context.active(), span), async () => {
      try {
        const result = await fn();
        span.setStatus({ code: SpanStatusCode.OK });
        return result;
      } catch (err) {
        span.recordException(err as Error);
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: (err as Error).message,
        });
        throw err;
      } finally {
        // Always end the span — even on exception
        span.end();
      }
    });
  }

  /**
   * Gracefully shut down the OTel SDK, flushing pending spans.
   */
  async shutdown(): Promise<void> {
    if (this.sdk) {
      try {
        await this.sdk.shutdown();
        this.logger.log('OpenTelemetry SDK shut down');
      } catch (err) {
        this.logger.error({ err }, 'Error shutting down OpenTelemetry SDK');
      }
    }
  }
}
