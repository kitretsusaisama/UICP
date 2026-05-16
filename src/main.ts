import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { ValidationPipe } from '@nestjs/common';
import { Logger } from 'nestjs-pino';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { SEMRESATTRS_SERVICE_NAME } from '@opentelemetry/semantic-conventions';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import compression from 'compression';
import { AppModule } from './app.module';
import * as net from 'net';

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

// Port pool configuration - dynamic port allocation with fallback
const START_PORT = parseInt(process.env['PORT'] ?? '3000', 10);
const PORT_POOL_SIZE = parseInt(process.env['PORT_POOL_SIZE'] ?? '100', 10);

function resolveCorsOrigin(): boolean | string[] {
  const configured = process.env['CORS_ORIGIN'] ?? process.env['CORS_ORIGINS'];
  if (configured) {
    return configured
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean);
  }

  return process.env['NODE_ENV'] === 'production' ? false : true;
}

function isSwaggerEnabled(): boolean {
  const configured = process.env['SWAGGER_ENABLED'];
  if (configured !== undefined) {
    return configured === 'true';
  }

  return process.env['NODE_ENV'] !== 'production';
}

async function isPortAvailable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.once('listening', () => {
      server.close();
      resolve(true);
    });
    server.listen(port, '0.0.0.0');
  });
}

async function findAvailablePort(app: Awaited<ReturnType<typeof NestFactory.create>>, maxAttempts = 10): Promise<number> {
  // Try primary port first (optimistic)
  if (await isPortAvailable(START_PORT)) {
    return START_PORT;
  }

  // Primary occupied: create shuffled pool indices [1..POOL_SIZE]
  const indices = Array.from({ length: PORT_POOL_SIZE }, (_, i) => i + 1);
  // Fisher-Yates shuffle
  for (let i = indices.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const temp = indices[i]!;
    indices[i] = indices[j]!;
    indices[j] = temp;
  }

  // Try shuffled ports with a limit
  for (const offset of indices.slice(0, maxAttempts)) {
    const port = START_PORT + offset;
    if (await isPortAvailable(port)) {
      return port;
    }
  }

  throw new Error(`No available port in range ${START_PORT}-${START_PORT + PORT_POOL_SIZE}`);
}

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

  // Security: Enable Helmet for HTTP headers hardening
  app.use(helmet());

  // Payload compression for responses > 1KB
  app.use(compression({
    threshold: 1024,
    level: 6, // balanced gzip level
  }));

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  // Enable CORS for frontend integration
  app.enableCors({
    origin: resolveCorsOrigin(),
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'x-tenant-id', 'x-tenant-slug', 'x-request-id'],
  });

  // Replace NestJS logger with Pino
  const logger = app.get(Logger);
  app.useLogger(logger);

  if (isSwaggerEnabled()) {
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

  // Dynamic port pool: try primary, fallback to random in pool
  const port = await findAvailablePort(app);

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

// Standalone logger for bootstrap errors (before app logger is available)
const bootstrapLogger = {
  error(msg: string, context?: string) {
    const timestamp = new Date().toISOString();
    console.error(`[${timestamp}] [${context ?? 'Bootstrap'}] ERROR: ${msg}`);
  },
};

bootstrap().catch((err: unknown) => {
  bootstrapLogger.error(`Fatal error during bootstrap: ${err instanceof Error ? err.message : String(err)}`, 'Bootstrap');
  process.exit(1);
});
