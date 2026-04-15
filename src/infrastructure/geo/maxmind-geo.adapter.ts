import { Injectable, Logger, OnModuleInit, Optional, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import { CircuitBreaker, CIRCUIT_BREAKER_CONFIGS } from '../resilience/circuit-breaker';
import { IMetricsPort } from '../../application/ports/driven/i-metrics.port';
import { INJECTION_TOKENS } from '../../application/ports/injection-tokens';

/**
 * Result of a GeoIP lookup.
 */
export interface GeoLocation {
  lat: number;
  lon: number;
  country: string;
  city: string;
}

/**
 * MaxMind GeoLite2 GeoIP adapter.
 *
 * - Wraps the `maxmind` npm package with a local GeoLite2-City database.
 * - Circuit breaker: 100ms timeout, 20% error threshold (Req 15.1).
 * - Returns `null` when the circuit is OPEN (geo score defaults to 0.0 in UEBA).
 * - Implements Req 11.4: local GeoIP DB for impossible travel detection.
 */
@Injectable()
export class MaxmindGeoAdapter implements OnModuleInit {
  private readonly logger = new Logger(MaxmindGeoAdapter.name);
  private reader: any = null;

  // ── Circuit Breaker ────────────────────────────────────────────────────────
  private readonly circuitBreaker: CircuitBreaker<GeoLocation | null>;

  private readonly ROLLING_WINDOW_MS = 10_000;
  private readonly ERROR_THRESHOLD_PERCENT = 20;
  private readonly VOLUME_THRESHOLD = 10;
  private readonly RESET_TIMEOUT_MS = 30_000;
  private readonly CALL_TIMEOUT_MS = 100;

  constructor(
    private readonly config: ConfigService,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
  ) {
    this.circuitBreaker = new CircuitBreaker(CIRCUIT_BREAKER_CONFIGS.geoip, metrics);
  }

  async onModuleInit(): Promise<void> {
    await this.loadDatabase();
  }

  /**
   * Look up the geographic location of an IP address.
   *
   * Returns `null` when:
   * - The circuit breaker is OPEN (Req 15.2: geo score defaults to 0.0)
   * - The IP is not found in the database (private/reserved ranges)
   * - The database is not loaded
   */
  async lookup(ip: string): Promise<GeoLocation | null> {
    if (!this.reader) {
      this.logger.warn('GeoIP database not loaded — returning null');
      return null;
    }

    // Circuit open — return null so UEBA geo score defaults to 0.0 (Req 15.2)
    if (this.circuitBreaker.isOpen()) {
      return null;
    }

    try {
      return await this.circuitBreaker.execute(() =>
        Promise.resolve(this.performLookup(ip)),
      );
    } catch (err: any) {
      if (err?.code === 'CIRCUIT_OPEN' || err?.code === 'CIRCUIT_TIMEOUT') {
        return null;
      }
      this.logger.warn({ err, ip: '[REDACTED]' }, 'GeoIP lookup failed');
      return null;
    }
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private performLookup(ip: string): GeoLocation | null {
    try {
      const record = this.reader.get(ip);
      if (!record) return null;

      const lat = record.location?.latitude ?? 0;
      const lon = record.location?.longitude ?? 0;
      const country = record.country?.iso_code ?? record.registered_country?.iso_code ?? '';
      const city = record.city?.names?.en ?? '';

      return { lat, lon, country, city };
    } catch {
      return null;
    }
  }

  private async loadDatabase(): Promise<void> {
    const dbPath = this.config.get<string>(
      'GEOIP_DB_PATH',
      path.join(process.cwd(), 'data', 'GeoLite2-City.mmdb'),
    );

    if (!fs.existsSync(dbPath)) {
      this.logger.warn(
        { dbPath },
        'GeoLite2-City.mmdb not found — GeoIP lookups will return null. ' +
        'Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data',
      );
      return;
    }

    try {
      // Dynamic require to avoid hard startup failure when maxmind is not installed
      const maxmind = require('maxmind');
      this.reader = await maxmind.open(dbPath);
      this.logger.log({ dbPath }, 'GeoLite2-City database loaded');
    } catch (err) {
      this.logger.error({ err }, 'Failed to load GeoLite2-City database');
    }
  }
}
