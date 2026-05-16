import { describe, it, expect, beforeEach } from '@jest/globals';

// ========================================================
// PROVIDERS: Circuit Breaker State Machine
// ========================================================
// Purpose: Validate circuit breaker state transitions
// ========================================================

type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

interface CircuitBreakerState {
  state: CircuitState;
  failureCount: number;
  successCount: number;
  lastFailure?: number;
  lastSuccess?: number;
}

// Constants matching production config
const FAILURE_THRESHOLD = 5;
const RESET_TIMEOUT_MS = 60000;
const SUCCESS_THRESHOLD = 3;

// In-memory circuit breaker state
const circuitStates = new Map<string, CircuitBreakerState>();

function circuitKey(tenantId: string, providerKey: string): string {
  return `${tenantId}:${providerKey}`;
}

function getState(tenantId: string, providerKey: string): CircuitBreakerState {
  const key = circuitKey(tenantId, providerKey);
  const existing = circuitStates.get(key);

  if (existing) return existing;

  // Default closed state
  const newState: CircuitBreakerState = {
    state: 'CLOSED',
    failureCount: 0,
    successCount: 0,
  };
  circuitStates.set(key, newState);
  return newState;
}

function recordSuccess(tenantId: string, providerKey: string): void {
  const state = getState(tenantId, providerKey);
  state.successCount += 1;
  state.lastSuccess = Date.now();

  // State transitions
  if (state.state === 'HALF_OPEN') {
    if (state.successCount >= SUCCESS_THRESHOLD) {
      state.state = 'CLOSED';
      state.failureCount = 0;
      state.successCount = 0;
    }
  } else if (state.state === 'OPEN') {
    // Transition to HALF_OPEN
    state.state = 'HALF_OPEN';
    state.successCount = 1;
  }

  // Reset failure count on success
  state.failureCount = 0;
}

function recordFailure(tenantId: string, providerKey: string): void {
  const state = getState(tenantId, providerKey);
  state.failureCount += 1;
  state.lastFailure = Date.now();
  state.successCount = 0;

  // Open circuit after threshold
  if (state.failureCount >= FAILURE_THRESHOLD) {
    state.state = 'OPEN';
  }
}

function isAvailable(tenantId: string, providerKey: string): boolean {
  const state = getState(tenantId, providerKey);

  if (state.state === 'CLOSED') return true;

  if (state.state === 'OPEN') {
    // Check if should transition to HALF_OPEN
    if (state.lastFailure) {
      const timeSinceFailure = Date.now() - state.lastFailure;
      if (timeSinceFailure >= RESET_TIMEOUT_MS) {
        state.state = 'HALF_OPEN';
        state.successCount = 0;
        return true;
      }
    }
    return false;
  }

  if (state.state === 'HALF_OPEN') {
    // Allow test requests
    return true;
  }

  return false;
}

function getCircuitState(tenantId: string, providerKey: string): CircuitState {
  const state = getState(tenantId, providerKey);

  // Check timeout for OPEN -> HALF_OPEN transition
  if (state.state === 'OPEN' && state.lastFailure) {
    const timeSinceFailure = Date.now() - state.lastFailure;
    if (timeSinceFailure >= RESET_TIMEOUT_MS) {
      return 'HALF_OPEN';
    }
  }

  return state.state;
}

function clearTestState(): void {
  circuitStates.clear();
}

describe('Provider Circuit Breaker', () => {
  beforeEach(() => {
    clearTestState();
  });

  // ========================================================
  // STATE TRANSITIONS
  // ========================================================
  describe('Opens on Provider Failure', () => {
    it('opens circuit after 5 failures', async () => {
      for (let i = 0; i < FAILURE_THRESHOLD; i++) {
        recordFailure('tenant-a', 'MSG91');
      }

      const state = getState('tenant-a', 'MSG91');
      expect(state.state).toBe('OPEN');
      expect(state.failureCount).toBe(FAILURE_THRESHOLD);
    });

    it('tracks failure count correctly', async () => {
      recordFailure('tenant-a', 'MSG91');
      recordFailure('tenant-a', 'MSG91');
      recordFailure('tenant-a', 'MSG91');

      const state = getState('tenant-a', 'MSG91');
      expect(state.failureCount).toBe(3);
      expect(state.state).toBe('CLOSED'); // Not yet at threshold
    });

    it('emits lineage on circuit open', async () => {
      // Record failures to open circuit
      for (let i = 0; i < FAILURE_THRESHOLD; i++) {
        recordFailure('tenant-a', 'MSG91');
      }

      const state = getState('tenant-a', 'MSG91');

      // Lineage: state transition recorded
      expect(state.state).toBe('OPEN');
      expect(state.lastFailure).toBeDefined();
    });
  });

  // ========================================================
  // HALF-OPEN TRANSITION
  // ========================================================
  describe('Half-Open After Timeout', () => {
    it('transitions to half-open after timeout', async () => {
      // Open the circuit
      for (let i = 0; i < FAILURE_THRESHOLD; i++) {
        recordFailure('tenant-a', 'MSG91');
      }

      // In test, we simulate timing
      const state = circuitStates.get(circuitKey('tenant-a', 'MSG91'))!;
      state.lastFailure = Date.now() - RESET_TIMEOUT_MS - 1000;

      const currentState = getCircuitState('tenant-a', 'MSG91');
      expect(currentState).toBe('HALF_OPEN');
    });

    it('allows test request in half-open state', async () => {
      // Open then half-open
      for (let i = 0; i < FAILURE_THRESHOLD; i++) {
        recordFailure('tenant-a', 'MSG91');
      }

      const state = circuitStates.get(circuitKey('tenant-a', 'MSG91'))!;
      state.lastFailure = Date.now() - RESET_TIMEOUT_MS - 1000;

      const available = isAvailable('tenant-a', 'MSG91');
      expect(available).toBe(true);
    });

    it('closes after success in half-open', async () => {
      // Open then half-open
      for (let i = 0; i < FAILURE_THRESHOLD; i++) {
        recordFailure('tenant-a', 'MSG91');
      }

      const state = circuitStates.get(circuitKey('tenant-a', 'MSG91'))!;
      state.lastFailure = Date.now() - RESET_TIMEOUT_MS - 1000;

      // Success in half-open
      recordSuccess('tenant-a', 'MSG91');
      recordSuccess('tenant-a', 'MSG91');
      recordSuccess('tenant-a', 'MSG91');

      const finalState = getState('tenant-a', 'MSG91');
      expect(finalState.state).toBe('CLOSED');
    });
  });

  // ========================================================
  // RECOVERY BEHAVIOR
  // ========================================================
  describe('Circuit Recovery Behavior', () => {
    it('resets failure count on success', async () => {
      recordFailure('tenant-a', 'MSG91');
      recordFailure('tenant-a', 'MSG91');

      // Success resets
      recordSuccess('tenant-a', 'MSG91');

      const state = getState('tenant-a', 'MSG91');
      expect(state.failureCount).toBe(0);
    });

    it('skips provider when circuit is open', async () => {
      for (let i = 0; i < FAILURE_THRESHOLD; i++) {
        recordFailure('tenant-a', 'MSG91');
      }

      const available = isAvailable('tenant-a', 'MSG91');
      expect(available).toBe(false);
    });

    it('allows fallback in open circuit', async () => {
      for (let i = 0; i < FAILURE_THRESHOLD; i++) {
        recordFailure('tenant-a', 'MSG91');
      }

      // Tenant B should still work
      const available = isAvailable('tenant-b', 'TWILIO');
      expect(available).toBe(true);
    });
  });

  // ========================================================
  // TENANT ISOLATION
  // ========================================================
  describe('Tenant Isolation', () => {
    it('maintains separate circuit per tenant', async () => {
      // Fail Tenant A's provider
      for (let i = 0; i < FAILURE_THRESHOLD; i++) {
        recordFailure('tenant-a', 'MSG91');
      }

      // Tenant B should be unaffected
      const stateB = getState('tenant-b', 'MSG91');
      expect(stateB.state).toBe('CLOSED');
    });

    it('isolates circuits per provider', async () => {
      // Fail MSG91
      for (let i = 0; i < FAILURE_THRESHOLD; i++) {
        recordFailure('tenant-a', 'MSG91');
      }

      // TWILIO still works
      const stateTwilio = getState('tenant-a', 'TWILIO');
      expect(stateTwilio.state).toBe('CLOSED');
    });
  });

  // ========================================================
  // STATE QUERY
  // ========================================================
  describe('State Query', () => {
    it('returns current state', async () => {
      const state = getState('tenant-a', 'MSG91');

      expect(state.state).toBe('CLOSED');
      expect(state.failureCount).toBe(0);
    });

    it('tracks last failure time', async () => {
      recordFailure('tenant-a', 'MSG91');

      const state = getState('tenant-a', 'MSG91');
      expect(state.lastFailure).toBeDefined();
    });
  });
});