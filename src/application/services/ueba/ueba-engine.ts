import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { createHmac } from 'crypto';
import { VelocityAnalyzer } from './velocity-analyzer';
import { GeoAnalyzer } from './geo-analyzer';
import { DeviceAnalyzer, DeviceSignals } from './device-analyzer';
import { CredentialStuffingAnalyzer } from './credential-stuffing-analyzer';
import { TorExitNodeChecker } from './tor-exit-node-checker';
import { ICachePort } from '../../ports/driven/i-cache.port';
import { IAlertRepository, KillChainStage, SignalResult, SocAlert } from '../../ports/driven/i-alert.repository';
import { IMetricsPort } from '../../ports/driven/i-metrics.port';
import { ITracerPort } from '../../ports/driven/i-tracer.port';
import { INJECTION_TOKENS } from '../../ports/injection-tokens';
import { UicpLogger } from '../../../shared/logger/pino-logger.service';
import { measure } from '../../../shared/logger/measure';

/** Input context for a UEBA scoring request. */
export interface UebaContext {
  /** HMAC of the IP address (never raw IP in logs). */
  ipHash: string;
  /** Raw IP address — used for GeoIP lookup and Tor check only. */
  ip: string;
  /** Device signals for fingerprinting. */
  deviceSignals: DeviceSignals;
  /** User ID (undefined for pre-auth scoring). */
  userId?: string;
  /** Tenant ID. */
  tenantId: string;
}

/** Result of a UEBA scoring evaluation. */
export interface UebaResult {
  /** Composite threat score in [0.0, 1.0]. */
  score: number;
  /** Kill-chain stage classification, or null if score is low. */
  killChainStage: KillChainStage | null;
  /** Per-signal breakdown. */
  signals: SignalResult[];
  /** Response actions taken (e.g. 'SOC_ALERT_CREATED', 'ACCOUNT_LOCKED'). */
  responseActions: string[];
  /** Device fingerprint computed during scoring. */
  deviceFingerprint: string;
}

/**
 * Composite weights (Section 10.2):
 *   velocity: 0.25, geo: 0.30, device: 0.20, credentialStuffing: 0.15, tor: 0.10
 */
const WEIGHTS = {
  velocity: 0.25,
  geo: 0.30,
  device: 0.20,
  credentialStuffing: 0.15,
  tor: 0.10,
} as const;

/** Redis key for account lock (Req 11.10). TTL configurable via env. */
const ACCOUNT_LOCK_TTL_S = 3600; // 1 hour default

/**
 * Orchestrates all five UEBA analyzers via Promise.allSettled() (partial-failure safe).
 * Computes weighted composite score, classifies kill-chain stage, creates SOC alerts,
 * and locks accounts when score exceeds thresholds.
 *
 * Thresholds:
 *   score > 0.75 → create SOC alert (Req 11.9)
 *   score > 0.90 → lock account in Redis (Req 11.10)
 *
 * Implements: Req 11.1–11.10
 */
@Injectable()
export class UebaEngine {
  private readonly logger = new Logger(UebaEngine.name);

  constructor(
    private readonly velocityAnalyzer: VelocityAnalyzer,
    private readonly geoAnalyzer: GeoAnalyzer,
    private readonly deviceAnalyzer: DeviceAnalyzer,
    private readonly credentialStuffingAnalyzer: CredentialStuffingAnalyzer,
    private readonly torExitNodeChecker: TorExitNodeChecker,
    @Inject(INJECTION_TOKENS.CACHE_PORT) private readonly cache: ICachePort,
    @Inject(INJECTION_TOKENS.ALERT_REPOSITORY) private readonly alertRepository: IAlertRepository,
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT) private readonly metrics?: IMetricsPort,
    @Optional() private readonly uicpLogger?: UicpLogger,
    @Optional() @Inject(INJECTION_TOKENS.TRACER_PORT) private readonly tracer?: ITracerPort,
  ) {}

  /**
   * Evaluates all five signals and returns the composite threat score.
   * Uses Promise.allSettled() so a single analyzer failure does not block scoring.
   * Failed signals default to 0.0 with a warning log.
   */
  async evaluate(ctx: UebaContext): Promise<UebaResult> {
    if (this.uicpLogger) {
      return measure(
        {
          logger: this.uicpLogger,
          operation: 'ueba_scoring',
          context: UebaEngine.name,
          extra: { ipHash: ctx.ipHash, tenantId: ctx.tenantId },
        },
        () => this._evaluateWithTracing(ctx),
      );
    }
    return this._evaluateWithTracing(ctx);
  }

  private _evaluateWithTracing(ctx: UebaContext): Promise<UebaResult> {
    if (this.tracer) {
      return this.tracer.withSpan(
        'ueba_evaluate',
        () => this.doEvaluate(ctx),
        {
          'service.name': 'uicp',
          'tenant.id': ctx.tenantId,
          'ueba.ip_hash': ctx.ipHash,
        },
      );
    }
    return this.doEvaluate(ctx);
  }

  private async doEvaluate(ctx: UebaContext): Promise<UebaResult> {
    const userId = ctx.userId ?? 'anonymous';

    // ── Collect all five signals in parallel ────────────────────────────────
    const [velocityResult, geoResult, deviceResult, csResult, torResult] =
      await Promise.allSettled([
        this.velocityAnalyzer.score(userId, ctx.ipHash),
        this.geoAnalyzer.score(ctx.ip, ctx.tenantId, userId),
        this.deviceAnalyzer.score(ctx.deviceSignals, ctx.tenantId, userId),
        this.credentialStuffingAnalyzer.score(ctx.ipHash, ctx.tenantId),
        this.torExitNodeChecker.score(ctx.ip),
      ]);

    // ── Extract scores (default 0.0 on failure) ─────────────────────────────
    const velocityScore = this.extractScore(velocityResult, 'velocity');
    const geoScore = this.extractScore(geoResult, 'geo');
    const deviceResult2 = deviceResult.status === 'fulfilled'
      ? deviceResult.value
      : { score: 0.0, fingerprint: '' };
    const deviceScore = deviceResult2.score;
    const csScore = this.extractScore(csResult, 'credentialStuffing');
    const torScore = this.extractScore(torResult, 'tor');

    if (deviceResult.status === 'rejected') {
      this.logger.warn({ err: deviceResult.reason }, 'DeviceAnalyzer failed — using 0.0');
      this.metrics?.increment('uicp_ueba_signal_failure_total', { signal: 'device' });
    }

    // ── Composite score (Section 10.2) ──────────────────────────────────────
    const rawScore =
      WEIGHTS.velocity * velocityScore +
      WEIGHTS.geo * geoScore +
      WEIGHTS.device * deviceScore +
      WEIGHTS.credentialStuffing * csScore +
      WEIGHTS.tor * torScore;

    const compositeScore = Math.min(1.0, Math.max(0.0, rawScore));

    // ── Kill-chain classification (Section 10.3) ────────────────────────────
    const killChainStage = this.classifyKillChain(
      compositeScore,
      velocityScore,
      geoScore,
      deviceScore,
      csScore,
    );

    // ── Signal breakdown ────────────────────────────────────────────────────
    const signals: SignalResult[] = [
      { signal: 'velocity',          score: velocityScore, detail: `weight=${WEIGHTS.velocity}` },
      { signal: 'geo',               score: geoScore,      detail: `weight=${WEIGHTS.geo}` },
      { signal: 'device',            score: deviceScore,   detail: `weight=${WEIGHTS.device}` },
      { signal: 'credentialStuffing',score: csScore,       detail: `weight=${WEIGHTS.credentialStuffing}` },
      { signal: 'tor',               score: torScore,      detail: `weight=${WEIGHTS.tor}` },
    ];

    const responseActions: string[] = [];

    // ── SOC alert when score > 0.75 (Req 11.9) ─────────────────────────────
    if (compositeScore > 0.75 && killChainStage !== null) {
      await this.createSocAlert(ctx, compositeScore, killChainStage, signals).catch((err) =>
        this.logger.error({ err }, 'Failed to create SOC alert'),
      );
      responseActions.push('SOC_ALERT_CREATED');
    }

    // ── Account lock when score > 0.90 (Req 11.10) ─────────────────────────
    if (compositeScore > 0.90 && ctx.userId) {
      await this.lockAccount(ctx.userId, ctx.tenantId).catch((err) =>
        this.logger.error({ err }, 'Failed to lock account'),
      );
      responseActions.push('ACCOUNT_LOCKED');
    }

    // ── Metrics ─────────────────────────────────────────────────────────────
    this.metrics?.histogram('uicp_ueba_composite_score', compositeScore, {
      tenant_id: ctx.tenantId,
    });
    if (killChainStage) {
      this.metrics?.increment('uicp_ueba_kill_chain_total', { stage: killChainStage });
    }

    // ── UEBA span attributes ─────────────────────────────────────────────────
    this.tracer?.setAttributes({
      'ueba.velocity_score': velocityScore,
      'ueba.geo_score': geoScore,
      'ueba.device_score': deviceScore,
      'ueba.composite_score': compositeScore,
      ...(killChainStage ? { 'ueba.kill_chain_stage': killChainStage } : {}),
    });

    return {
      score: compositeScore,
      killChainStage,
      signals,
      responseActions,
      deviceFingerprint: deviceResult2.fingerprint,
    };
  }

  private extractScore(
    result: PromiseSettledResult<number>,
    name: string,
  ): number {
    if (result.status === 'fulfilled') return result.value;
    this.logger.warn({ signal: name, err: result.reason }, 'UEBA signal failed — using 0.0');
    this.metrics?.increment('uicp_ueba_signal_failure_total', { signal: name });
    return 0.0;
  }

  /**
   * Kill-chain decision tree (Section 10.3).
   */
  private classifyKillChain(
    compositeScore: number,
    velocityScore: number,
    geoScore: number,
    deviceScore: number,
    csScore: number,
  ): KillChainStage | null {
    if (csScore > 0.7) return 'CREDENTIAL_ACCESS';
    if (geoScore === 1.0 && compositeScore > 0.7) return 'ACCOUNT_TAKEOVER';
    if (geoScore > 0.5 && deviceScore > 0.4) return 'LATERAL_MOVEMENT';
    if (velocityScore > 0.6 && deviceScore > 0.3) return 'INITIAL_ACCESS';
    if (compositeScore > 0.3) return 'RECONNAISSANCE';
    return null;
  }

  private async createSocAlert(
    ctx: UebaContext,
    threatScore: number,
    killChainStage: KillChainStage,
    signals: SignalResult[],
  ): Promise<void> {
    const alert: SocAlert = {
      id: randomUUID(),
      tenantId: ctx.tenantId,
      userId: ctx.userId,
      ipHash: ctx.ipHash,
      threatScore,
      killChainStage,
      signals,
      workflow: 'OPEN',
      checksum: this.computeChecksum({
        tenantId: ctx.tenantId,
        userId: ctx.userId,
        ipHash: ctx.ipHash,
        threatScore,
        killChainStage,
      }),
      createdAt: new Date(),
    };

    await this.alertRepository.save(alert);
    this.logger.warn(
      { alertId: alert.id, threatScore, killChainStage },
      'SOC alert created',
    );
  }

  private async lockAccount(userId: string, tenantId: string): Promise<void> {
    const lockKey = `account-lock:${tenantId}:${userId}`;
    await this.cache.set(lockKey, '1', ACCOUNT_LOCK_TTL_S);
    this.logger.warn({ userId, tenantId }, 'Account locked due to high threat score');
    this.metrics?.increment('uicp_account_lock_total', { tenant_id: tenantId });
  }

  /**
   * Computes a deterministic HMAC checksum over the immutable alert fields.
   * Uses a fixed key derived from the alert content (no secret needed for integrity check).
   */
  private computeChecksum(fields: Record<string, unknown>): string {
    const payload = JSON.stringify(fields, Object.keys(fields).sort());
    return createHmac('sha256', 'uicp-alert-integrity').update(payload).digest('hex');
  }
}
