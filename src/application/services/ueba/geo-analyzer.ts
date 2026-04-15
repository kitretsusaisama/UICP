import { Injectable, Logger } from '@nestjs/common';
import { ICachePort } from '../../ports/driven/i-cache.port';
import { MaxmindGeoAdapter, GeoLocation } from '../../../infrastructure/geo/maxmind-geo.adapter';
import { haversine } from '../../../shared/utils/haversine';

/** Stored geo baseline for a user. */
export interface GeoBaseline {
  lat: number;
  lon: number;
  country: string;
  city: string;
  updatedAt: string; // ISO timestamp
}

/**
 * Analyzes geographic anomalies in login attempts.
 *
 * Scoring (Section 10.1):
 *   - Impossible travel (speed > 900 km/h): 1.0
 *   - Country changed:                       0.6
 *   - City changed:                          0.2
 *   - Same location:                         0.0
 *   - No baseline (first login):             0.1
 *
 * Baseline key: geo-baseline:{tenantId}:{userId}  TTL: 30 days
 *
 * Implements: Req 11.3, Req 11.4
 */
@Injectable()
export class GeoAnalyzer {
  private readonly logger = new Logger(GeoAnalyzer.name);

  /** Impossible travel threshold in km/h (commercial flight max speed). */
  private static readonly IMPOSSIBLE_TRAVEL_KMH = 900;

  /** Baseline TTL: 30 days in seconds. */
  private static readonly BASELINE_TTL_S = 30 * 24 * 60 * 60;

  constructor(
    private readonly cache: ICachePort,
    private readonly geoAdapter: MaxmindGeoAdapter,
  ) {}

  /**
   * Computes the geo anomaly score for a login attempt.
   * Does NOT update the baseline — call `updateBaseline()` after a successful login.
   */
  async score(ip: string, tenantId: string, userId: string): Promise<number> {
    const current = await this.geoAdapter.lookup(ip);

    if (!current) {
      // GeoIP unavailable (circuit open or DB missing) — default to 0.0
      return 0.0;
    }

    const baselineKey = `geo-baseline:${tenantId}:${userId}`;
    const baselineRaw = await this.cache.get(baselineKey).catch(() => null);

    if (!baselineRaw) {
      // First login — slight elevation for unknown location
      return 0.1;
    }

    let baseline: GeoBaseline;
    try {
      baseline = JSON.parse(baselineRaw) as GeoBaseline;
    } catch {
      this.logger.warn({ baselineKey }, 'Failed to parse geo baseline — treating as first login');
      return 0.1;
    }

    const timeDeltaHours = this.timeSinceBaseline(baseline.updatedAt);

    if (timeDeltaHours > 0) {
      const distanceKm = haversine(
        { lat: baseline.lat, lon: baseline.lon },
        { lat: current.lat, lon: current.lon },
      );
      const speedKmh = distanceKm / timeDeltaHours;

      if (speedKmh > GeoAnalyzer.IMPOSSIBLE_TRAVEL_KMH) {
        this.logger.warn(
          { speedKmh: speedKmh.toFixed(0), distanceKm: distanceKm.toFixed(0) },
          'Impossible travel detected',
        );
        return 1.0;
      }
    }

    if (current.country !== baseline.country) {
      return 0.6;
    }

    if (current.city !== baseline.city) {
      return 0.2;
    }

    return 0.0;
  }

  /**
   * Updates the geo baseline after a successful login.
   * Refreshes the 30-day TTL.
   */
  async updateBaseline(ip: string, tenantId: string, userId: string): Promise<void> {
    const location = await this.geoAdapter.lookup(ip).catch(() => null);
    if (!location) return;

    const baseline: GeoBaseline = {
      lat: location.lat,
      lon: location.lon,
      country: location.country,
      city: location.city,
      updatedAt: new Date().toISOString(),
    };

    const key = `geo-baseline:${tenantId}:${userId}`;
    await this.cache
      .set(key, JSON.stringify(baseline), GeoAnalyzer.BASELINE_TTL_S)
      .catch((err) => this.logger.warn({ err }, 'Failed to update geo baseline'));
  }

  // ── Private ──────────────────────────────────────────────────────────────

  private timeSinceBaseline(updatedAt: string): number {
    const then = new Date(updatedAt).getTime();
    const now = Date.now();
    const deltaMs = now - then;
    return deltaMs / (1000 * 60 * 60); // convert to hours
  }
}
