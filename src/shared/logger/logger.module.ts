import { Module } from '@nestjs/common';
import { LoggerModule as PinoLoggerModule } from 'nestjs-pino';
import { ClsModule } from 'nestjs-cls';
import { UicpLogger } from './pino-logger.service';

/**
 * LoggerModule — configures nestjs-pino with:
 *   - NDJSON output in production, pino-pretty in development
 *   - pino-redact for PII paths (email, password, phone, ip, nested variants)
 *   - LOG_LEVEL env var support (defaults to 'info')
 *   - Exports UicpLogger for CLS-aware child logging
 *
 * Implements: Req 1 (audit trail), Req 13.6
 */
@Module({
  imports: [
    PinoLoggerModule.forRoot({
      pinoHttp: {
        // LOG_LEVEL env var controls verbosity; default 'info' in prod, 'debug' elsewhere
        level: process.env['LOG_LEVEL'] ?? (process.env['NODE_ENV'] === 'production' ? 'info' : 'debug'),

        // NDJSON in production; pino-pretty for local development
        transport:
          process.env['NODE_ENV'] !== 'production'
            ? { target: 'pino-pretty', options: { colorize: true, singleLine: false } }
            : undefined,

        // pino-redact: strip PII from all log lines — never log raw email, phone, password, or IP
        redact: {
          paths: [
            // Top-level fields
            'email',
            'password',
            'phone',
            'ip',
            // Nested variants (e.g. req.body.email, user.email)
            '*.email',
            '*.phone',
            '*.password',
            '*.ip',
            // HTTP request body / headers
            'req.headers.authorization',
            'req.headers["x-api-key"]',
            'req.body.password',
            'req.body.currentPassword',
            'req.body.newPassword',
            'req.body.email',
            'req.body.phone',
          ],
          censor: '[REDACTED]',
        },

        // Minimal request serializer — no raw IPs in logs
        serializers: {
          req(req: { id: string; method: string; url: string }) {
            return { id: req.id, method: req.method, url: req.url };
          },
          // Suppress raw response body from pino-http
          res(res: { statusCode: number }) {
            return { statusCode: res.statusCode };
          },
        },

        // Auto-generate request ID if not present
        genReqId(req: { headers: Record<string, string | string[] | undefined> }) {
          const xReqId = req.headers['x-request-id'];
          return (Array.isArray(xReqId) ? xReqId[0] : xReqId) ?? crypto.randomUUID();
        },
      },
    }),
    ClsModule,
  ],
  providers: [UicpLogger],
  exports: [PinoLoggerModule, UicpLogger],
})
export class LoggerModule {}
