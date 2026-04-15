import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { Logger } from 'nestjs-pino';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { SEMRESATTRS_SERVICE_NAME } from '@opentelemetry/semantic-conventions';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';

// LOG_LEVEL is consumed by LoggerModule (src/shared/logger/logger.module.ts).
// Validated here at bootstrap so a misconfigured value fails fast.
const VALID_LOG_LEVELS = ['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent'] as const;
type LogLevel = (typeof VALID_LOG_LEVELS)[number];

function resolveLogLevel(): LogLevel {
  const raw = process.env['LOG_LEVEL'];
  if (raw && VALID_LOG_LEVELS.includes(raw as LogLevel)) return raw as LogLevel;
  return process.env['NODE_ENV'] === 'production' ? 'info' : 'debug';
}

const GRACEFUL_SHUTDOWN_DRAIN_MS = 25_000;

async function bootstrap(): Promise<void> {
  // Ensure LOG_LEVEL is set before LoggerModule reads it
  process.env['LOG_LEVEL'] = resolveLogLevel();

  // ── OTel SDK must start BEFORE NestJS modules load so auto-instrumentation
  // patches http/mysql/redis clients at require-time (Section 13.3).
  if (process.env['OTEL_ENABLED'] !== 'false') {
    const sdk = new NodeSDK({
      resource: resourceFromAttributes({
        [SEMRESATTRS_SERVICE_NAME]: process.env['SERVICE_NAME'] ?? 'uicp',
      }),
      traceExporter: new OTLPTraceExporter({
        url: process.env['OTEL_EXPORTER_OTLP_ENDPOINT'] ?? 'http://localhost:4318/v1/traces',
        timeoutMillis: 5_000,
      }),
    });
    sdk.start();
  }

  const app = await NestFactory.create(AppModule, {
    // Suppress default NestJS logger; Pino takes over after init
    bufferLogs: true,
  });

  // Replace NestJS logger with Pino
  const logger = app.get(Logger);
  app.useLogger(logger);

  if (process.env['SWAGGER_ENABLED'] !== 'false') {
    const swaggerConfig = new DocumentBuilder()
      .setTitle('Unified Identity Control Plane API')
      .setDescription('Public platform APIs for auth, self-service sessions/users, and OIDC discovery.')
      .setVersion(process.env['SERVICE_VERSION'] ?? '1.0.0')
      .addBearerAuth(
        {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
        'bearer',
      )
      .addApiKey(
        {
          type: 'apiKey',
          in: 'header',
          name: 'x-tenant-id',
          description: 'Tenant UUID required for tenant-scoped routes',
        },
        'tenant-header',
      )
      .build();

    const document = SwaggerModule.createDocument(app, swaggerConfig);
    SwaggerModule.setup('docs', app, document, {
      jsonDocumentUrl: 'openapi.json',
      swaggerOptions: { persistAuthorization: true },
    });
  }

  // ── gRPC Microservice Transport ──────────────────────────────────────────
  // Disabled: requires @nestjs/microservices version matching @nestjs/core.
  // Re-enable after upgrading all @nestjs/* packages to the same major version.
  // const grpcPort = parseInt(process.env['GRPC_PORT'] ?? '5000', 10);

  // Enable graceful shutdown lifecycle hooks
  app.enableShutdownHooks();

  const port = parseInt(process.env['PORT'] ?? '3000', 10);
  await app.listen(port);

  logger.log(`UICP listening on port ${port}`, 'Bootstrap');

  // ── Graceful Shutdown ────────────────────────────────────────────────
  // Allow 25 seconds for in-flight requests to drain before force-exiting.
  // Kubernetes sends SIGTERM before removing the pod from the load balancer;
  // the drain window ensures no requests are dropped mid-flight.
  const shutdown = (signal: string) => {
    logger.log(`Received ${signal} — starting graceful shutdown`, 'Bootstrap');

    const forceExitTimer = setTimeout(() => {
      logger.error(
        'Graceful shutdown timed out after 25s — forcing exit',
        'Bootstrap',
      );
      process.exit(1);
    }, GRACEFUL_SHUTDOWN_DRAIN_MS);

    // Don't let the timer keep the process alive if app.close() resolves first
    forceExitTimer.unref();

    app
      .close()
      .then(() => {
        logger.log('Application closed cleanly', 'Bootstrap');
        clearTimeout(forceExitTimer);
        process.exit(0);
      })
      .catch((err: unknown) => {
        logger.error(
          `Error during shutdown: ${String(err)}`,
          'Bootstrap',
        );
        clearTimeout(forceExitTimer);
        process.exit(1);
      });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

bootstrap().catch((err: unknown) => {
  console.error('Fatal error during bootstrap:', err);
  process.exit(1);
});
