import { CircuitBreaker, CircuitBreakerConfig } from './circuit-breaker';
import { IMetricsPort } from '../../application/ports/driven/i-metrics.port';

// ── Helpers ────────────────────────────────────────────────────────────────

/** Minimal config that trips quickly for unit tests. */
function makeConfig(overrides: Partial<CircuitBreakerConfig> = {}): CircuitBreakerConfig {
  return {
    name: 'test',
    timeoutMs: 1_000,
    errorThresholdPercent: 50,
    volumeThreshold: 4,
    resetTimeoutMs: 100,
    rollingWindowMs: 10_000,
    ...overrides,
  };
}

function makeMetrics(): jest.Mocked<IMetricsPort> {
  return {
    increment: jest.fn(),
    gauge: jest.fn(),
    histogram: jest.fn(),
    observe: jest.fn(),
  };
}

const fail = () => Promise.reject(new Error('boom'));
const succeed = () => Promise.resolve('ok');

/** Drive the breaker to OPEN by exceeding volumeThreshold with 100% errors. */
async function tripOpen(cb: CircuitBreaker): Promise<void> {
  const cfg = (cb as any).config as CircuitBreakerConfig;
  for (let i = 0; i < cfg.volumeThreshold; i++) {
    await cb.execute(fail).catch(() => {});
  }
}

/** Advance the internal clock past resetTimeoutMs so OPEN → HALF_OPEN. */
function advancePastReset(cb: CircuitBreaker): void {
  const cfg = (cb as any).config as CircuitBreakerConfig;
  (cb as any).openedAt = Date.now() - cfg.resetTimeoutMs - 1;
}

// ── State machine tests ────────────────────────────────────────────────────

describe('CircuitBreaker — state machine', () => {
  // ── CLOSED → OPEN ──────────────────────────────────────────────────────

  describe('CLOSED → OPEN', () => {
    it('starts in CLOSED state', () => {
      const cb = new CircuitBreaker(makeConfig());
      expect(cb.getState()).toBe('CLOSED');
      expect(cb.isOpen()).toBe(false);
    });

    it('stays CLOSED when error rate is below threshold', async () => {
      const cb = new CircuitBreaker(makeConfig({ errorThresholdPercent: 50, volumeThreshold: 4 }));

      // 1 failure out of 4 calls = 25% — below 50% threshold
      await cb.execute(fail).catch(() => {});
      await cb.execute(succeed);
      await cb.execute(succeed);
      await cb.execute(succeed);

      expect(cb.getState()).toBe('CLOSED');
    });

    it('stays CLOSED when call count is below volumeThreshold', async () => {
      const cb = new CircuitBreaker(makeConfig({ volumeThreshold: 10, errorThresholdPercent: 50 }));

      // 3 failures but volumeThreshold is 10 — should not trip
      for (let i = 0; i < 3; i++) {
        await cb.execute(fail).catch(() => {});
      }

      expect(cb.getState()).toBe('CLOSED');
    });

    it('trips OPEN when error rate exceeds threshold after volumeThreshold calls', async () => {
      const cb = new CircuitBreaker(makeConfig({ volumeThreshold: 4, errorThresholdPercent: 50 }));

      // 4 failures out of 4 calls = 100% — exceeds 50% threshold
      await tripOpen(cb);

      expect(cb.getState()).toBe('OPEN');
      expect(cb.isOpen()).toBe(true);
    });

    it('trips OPEN exactly at the error threshold boundary', async () => {
      // volumeThreshold=4, errorThresholdPercent=50 → trips when failures/total >= 0.5
      const cb = new CircuitBreaker(makeConfig({ volumeThreshold: 4, errorThresholdPercent: 50 }));

      // 2 successes then 2 failures = 50% error rate — should trip
      await cb.execute(succeed);
      await cb.execute(succeed);
      await cb.execute(fail).catch(() => {});
      await cb.execute(fail).catch(() => {});

      expect(cb.getState()).toBe('OPEN');
    });

    it('throws CIRCUIT_OPEN error when circuit is OPEN', async () => {
      const cb = new CircuitBreaker(makeConfig());
      await tripOpen(cb);

      await expect(cb.execute(succeed)).rejects.toMatchObject({ code: 'CIRCUIT_OPEN' });
    });

    it('does not invoke the wrapped function when circuit is OPEN', async () => {
      const cb = new CircuitBreaker(makeConfig());
      await tripOpen(cb);

      const fn = jest.fn().mockResolvedValue('result');
      await cb.execute(fn).catch(() => {});

      expect(fn).not.toHaveBeenCalled();
    });
  });

  // ── OPEN → HALF_OPEN ───────────────────────────────────────────────────

  describe('OPEN → HALF_OPEN', () => {
    it('transitions to HALF_OPEN after resetTimeoutMs elapses', async () => {
      const cb = new CircuitBreaker(makeConfig({ resetTimeoutMs: 50 }));
      await tripOpen(cb);
      expect(cb.getState()).toBe('OPEN');

      advancePastReset(cb);

      expect(cb.getState()).toBe('HALF_OPEN');
    });

    it('remains OPEN before resetTimeoutMs elapses', async () => {
      const cb = new CircuitBreaker(makeConfig({ resetTimeoutMs: 60_000 }));
      await tripOpen(cb);

      // Only a few ms have passed — should still be OPEN
      expect(cb.getState()).toBe('OPEN');
    });

    it('allows a probe call through when in HALF_OPEN state', async () => {
      const cb = new CircuitBreaker(makeConfig());
      await tripOpen(cb);
      advancePastReset(cb);

      // Should not throw CIRCUIT_OPEN — the probe is allowed through
      const fn = jest.fn().mockResolvedValue('probe-result');
      await expect(cb.execute(fn)).resolves.toBe('probe-result');
      expect(fn).toHaveBeenCalledTimes(1);
    });
  });

  // ── HALF_OPEN → CLOSED ─────────────────────────────────────────────────

  describe('HALF_OPEN → CLOSED', () => {
    it('transitions to CLOSED when the probe call succeeds', async () => {
      const cb = new CircuitBreaker(makeConfig());
      await tripOpen(cb);
      advancePastReset(cb);

      await cb.execute(succeed);

      expect(cb.getState()).toBe('CLOSED');
      expect(cb.isOpen()).toBe(false);
    });

    it('resets failure counters after recovering to CLOSED', async () => {
      const cb = new CircuitBreaker(makeConfig({ volumeThreshold: 4, errorThresholdPercent: 50 }));
      await tripOpen(cb);
      advancePastReset(cb);

      // Probe succeeds → CLOSED
      await cb.execute(succeed);
      expect(cb.getState()).toBe('CLOSED');

      // A single failure after recovery should not re-trip (counters reset)
      await cb.execute(fail).catch(() => {});
      expect(cb.getState()).toBe('CLOSED');
    });

    it('can be tripped OPEN again after recovering to CLOSED', async () => {
      const cb = new CircuitBreaker(makeConfig());
      await tripOpen(cb);
      advancePastReset(cb);
      await cb.execute(succeed); // recover
      expect(cb.getState()).toBe('CLOSED');

      // Trip again
      await tripOpen(cb);
      expect(cb.getState()).toBe('OPEN');
    });
  });

  // ── HALF_OPEN → OPEN ───────────────────────────────────────────────────

  describe('HALF_OPEN → OPEN', () => {
    it('transitions back to OPEN when the probe call fails', async () => {
      const cb = new CircuitBreaker(makeConfig());
      await tripOpen(cb);
      advancePastReset(cb);

      await cb.execute(fail).catch(() => {});

      expect(cb.getState()).toBe('OPEN');
    });

    it('resets the openedAt timer when re-entering OPEN from HALF_OPEN', async () => {
      const cb = new CircuitBreaker(makeConfig({ resetTimeoutMs: 100 }));
      await tripOpen(cb);
      advancePastReset(cb);

      // Probe fails → back to OPEN with fresh openedAt
      await cb.execute(fail).catch(() => {});
      expect(cb.getState()).toBe('OPEN');

      // Should NOT immediately transition to HALF_OPEN (timer just reset)
      expect((cb as any).openedAt).toBeGreaterThan(Date.now() - 50);
    });

    it('throws CIRCUIT_OPEN after probe failure re-opens the circuit', async () => {
      const cb = new CircuitBreaker(makeConfig());
      await tripOpen(cb);
      advancePastReset(cb);

      await cb.execute(fail).catch(() => {}); // probe fails → OPEN

      await expect(cb.execute(succeed)).rejects.toMatchObject({ code: 'CIRCUIT_OPEN' });
    });
  });
});

// ── Fallback tests ─────────────────────────────────────────────────────────

describe('CircuitBreaker — fallback invocation', () => {
  it('invokes fallback when circuit is OPEN', async () => {
    const cb = new CircuitBreaker(makeConfig());
    await tripOpen(cb);

    const fallback = jest.fn().mockResolvedValue('fallback-result');

    // Simulate caller-side fallback pattern (the breaker throws; caller catches and calls fallback)
    let result: string | undefined;
    try {
      result = (await cb.execute(succeed)) as string;
    } catch (err: any) {
      if (err.code === 'CIRCUIT_OPEN') {
        result = await fallback();
      }
    }

    expect(fallback).toHaveBeenCalledTimes(1);
    expect(result).toBe('fallback-result');
  });

  it('does not invoke fallback when circuit is CLOSED', async () => {
    const cb = new CircuitBreaker(makeConfig());
    const fallback = jest.fn().mockResolvedValue('fallback-result');

    let result: string | undefined;
    try {
      result = await cb.execute(succeed) as string;
    } catch (err: any) {
      if (err.code === 'CIRCUIT_OPEN') {
        result = await fallback();
      }
    }

    expect(fallback).not.toHaveBeenCalled();
    expect(result).toBe('ok');
  });

  it('does not invoke fallback when circuit is HALF_OPEN and probe succeeds', async () => {
    const cb = new CircuitBreaker(makeConfig());
    await tripOpen(cb);
    advancePastReset(cb);

    const fallback = jest.fn().mockResolvedValue('fallback-result');

    let result: string | undefined;
    try {
      result = await cb.execute(succeed) as string;
    } catch (err: any) {
      if (err.code === 'CIRCUIT_OPEN') {
        result = await fallback();
      }
    }

    expect(fallback).not.toHaveBeenCalled();
    expect(result).toBe('ok');
  });

  it('invokes fallback when HALF_OPEN probe fails and circuit re-opens', async () => {
    const cb = new CircuitBreaker(makeConfig());
    await tripOpen(cb);
    advancePastReset(cb);

    // Probe fails → OPEN
    await cb.execute(fail).catch(() => {});

    const fallback = jest.fn().mockResolvedValue('fallback-after-reopen');

    let result: string | undefined;
    try {
      result = (await cb.execute(succeed)) as string;
    } catch (err: any) {
      if (err.code === 'CIRCUIT_OPEN') {
        result = await fallback();
      }
    }

    expect(fallback).toHaveBeenCalledTimes(1);
    expect(result).toBe('fallback-after-reopen');
  });
});

// ── Metrics emission tests ─────────────────────────────────────────────────

describe('CircuitBreaker — metrics emission (Req 15.3)', () => {
  it('emits gauge=1 and increments fire counter when tripping OPEN', async () => {
    const metrics = makeMetrics();
    const cb = new CircuitBreaker(makeConfig(), metrics);

    await tripOpen(cb);

    expect(metrics.gauge).toHaveBeenCalledWith(
      'uicp_circuit_breaker_state',
      1,
      { name: 'test' },
    );
    expect(metrics.increment).toHaveBeenCalledWith(
      'uicp_circuit_breaker_fire_total',
      { name: 'test' },
    );
  });

  it('emits gauge=0.5 when transitioning to HALF_OPEN', async () => {
    const metrics = makeMetrics();
    const cb = new CircuitBreaker(makeConfig(), metrics);

    await tripOpen(cb);
    advancePastReset(cb);
    cb.getState(); // triggers the OPEN → HALF_OPEN transition

    expect(metrics.gauge).toHaveBeenCalledWith(
      'uicp_circuit_breaker_state',
      0.5,
      { name: 'test' },
    );
  });

  it('emits gauge=0 when recovering to CLOSED', async () => {
    const metrics = makeMetrics();
    const cb = new CircuitBreaker(makeConfig(), metrics);

    await tripOpen(cb);
    advancePastReset(cb);
    await cb.execute(succeed); // probe succeeds → CLOSED

    expect(metrics.gauge).toHaveBeenCalledWith(
      'uicp_circuit_breaker_state',
      0,
      { name: 'test' },
    );
  });
});

// ── Timeout tests ──────────────────────────────────────────────────────────

describe('CircuitBreaker — call timeout', () => {
  it('throws CIRCUIT_TIMEOUT when the wrapped call exceeds timeoutMs', async () => {
    const cb = new CircuitBreaker(makeConfig({ timeoutMs: 20 }));

    const slowFn = () => new Promise<string>((resolve) => setTimeout(() => resolve('late'), 200));

    await expect(cb.execute(slowFn)).rejects.toMatchObject({ code: 'CIRCUIT_TIMEOUT' });
  }, 1_000);

  it('counts a timeout as a failure for threshold tracking', async () => {
    const cb = new CircuitBreaker(
      makeConfig({ timeoutMs: 20, volumeThreshold: 4, errorThresholdPercent: 50 }),
    );

    const slowFn = () => new Promise<string>((resolve) => setTimeout(() => resolve('late'), 200));

    for (let i = 0; i < 4; i++) {
      await cb.execute(slowFn).catch(() => {});
    }

    expect(cb.getState()).toBe('OPEN');
  }, 5_000);
});
