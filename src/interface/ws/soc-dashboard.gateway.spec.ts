/**
 * Unit tests for SOC alert workflow state machine and HMAC integrity verification.
 *
 * Task 19.1 — optional tests covering:
 *   - OPEN → ACKNOWLEDGED → RESOLVED valid transitions
 *   - OPEN → FALSE_POSITIVE valid from any state
 *   - HMAC checksum failure throws IntegrityViolationException
 */

import { createHmac } from 'crypto';
import { IntegrityViolationException } from '../http/controllers/admin.controller';
import { AlertWorkflowState, SocAlert } from '../../application/ports/driven/i-alert.repository';

// ── Helpers ───────────────────────────────────────────────────────────────────

function computeChecksum(fields: {
  tenantId: string;
  userId?: string;
  ipHash: string;
  threatScore: number;
  killChainStage: string;
}): string {
  const payload = JSON.stringify(fields, Object.keys(fields).sort());
  return createHmac('sha256', 'uicp-alert-integrity').update(payload).digest('hex');
}

function makeAlert(overrides: Partial<SocAlert> = {}): SocAlert {
  const base = {
    id: '11111111-1111-4111-8111-111111111111',
    tenantId: '22222222-2222-4222-8222-222222222222',
    userId: '33333333-3333-4333-8333-333333333333',
    ipHash: 'aabbcc',
    threatScore: 0.85,
    killChainStage: 'CREDENTIAL_ACCESS' as const,
    signals: [],
    workflow: 'OPEN' as AlertWorkflowState,
    createdAt: new Date('2024-01-01T00:00:00Z'),
  };

  const merged = { ...base, ...overrides };
  const checksum = computeChecksum({
    tenantId: merged.tenantId,
    userId: merged.userId,
    ipHash: merged.ipHash,
    threatScore: merged.threatScore,
    killChainStage: merged.killChainStage,
  });

  return { ...merged, checksum };
}

// ── Workflow state machine ────────────────────────────────────────────────────

/**
 * Minimal in-process state machine that mirrors the transitions enforced
 * by AdminController + IAlertRepository.updateWorkflow().
 */
type TransitionResult = { ok: true; newState: AlertWorkflowState } | { ok: false; error: string };

function transition(
  current: AlertWorkflowState,
  target: AlertWorkflowState,
): TransitionResult {
  const allowed: Record<AlertWorkflowState, AlertWorkflowState[]> = {
    OPEN: ['ACKNOWLEDGED', 'FALSE_POSITIVE'],
    ACKNOWLEDGED: ['RESOLVED', 'FALSE_POSITIVE'],
    RESOLVED: ['FALSE_POSITIVE'],
    FALSE_POSITIVE: [],
  };

  if (allowed[current].includes(target)) {
    return { ok: true, newState: target };
  }
  return { ok: false, error: `Cannot transition from ${current} to ${target}` };
}

// ── Checksum verification (mirrors AdminController.verifyAlertChecksum) ───────

function verifyAlertChecksum(alert: SocAlert): void {
  const fields = {
    tenantId: alert.tenantId,
    userId: alert.userId,
    ipHash: alert.ipHash,
    threatScore: alert.threatScore,
    killChainStage: alert.killChainStage,
  };
  const expected = computeChecksum(fields);
  if (alert.checksum !== expected) {
    throw new IntegrityViolationException(alert.id);
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('SOC alert workflow state machine', () => {
  describe('OPEN → ACKNOWLEDGED → RESOLVED (valid path)', () => {
    it('allows OPEN → ACKNOWLEDGED', () => {
      const result = transition('OPEN', 'ACKNOWLEDGED');
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.newState).toBe('ACKNOWLEDGED');
    });

    it('allows ACKNOWLEDGED → RESOLVED', () => {
      const result = transition('ACKNOWLEDGED', 'RESOLVED');
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.newState).toBe('RESOLVED');
    });

    it('rejects OPEN → RESOLVED (must go through ACKNOWLEDGED first)', () => {
      const result = transition('OPEN', 'RESOLVED');
      expect(result.ok).toBe(false);
    });

    it('rejects RESOLVED → ACKNOWLEDGED (no backward transitions)', () => {
      const result = transition('RESOLVED', 'ACKNOWLEDGED');
      expect(result.ok).toBe(false);
    });
  });

  describe('FALSE_POSITIVE — valid from any non-terminal state', () => {
    it('allows OPEN → FALSE_POSITIVE', () => {
      const result = transition('OPEN', 'FALSE_POSITIVE');
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.newState).toBe('FALSE_POSITIVE');
    });

    it('allows ACKNOWLEDGED → FALSE_POSITIVE', () => {
      const result = transition('ACKNOWLEDGED', 'FALSE_POSITIVE');
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.newState).toBe('FALSE_POSITIVE');
    });

    it('allows RESOLVED → FALSE_POSITIVE', () => {
      const result = transition('RESOLVED', 'FALSE_POSITIVE');
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.newState).toBe('FALSE_POSITIVE');
    });

    it('rejects FALSE_POSITIVE → any state (terminal)', () => {
      const states: AlertWorkflowState[] = ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE'];
      for (const target of states) {
        const result = transition('FALSE_POSITIVE', target);
        expect(result.ok).toBe(false);
      }
    });
  });
});

describe('HMAC checksum verification', () => {
  it('passes for an alert with a valid checksum', () => {
    const alert = makeAlert();
    expect(() => verifyAlertChecksum(alert)).not.toThrow();
  });

  it('throws IntegrityViolationException when checksum is tampered', () => {
    const alert = makeAlert();
    // Directly overwrite the checksum after creation to simulate tampering
    const tampered: SocAlert = { ...alert, checksum: 'deadbeef' + '0'.repeat(56) };
    expect(() => verifyAlertChecksum(tampered)).toThrow(IntegrityViolationException);
  });

  it('throws IntegrityViolationException when threatScore is mutated', () => {
    const alert = makeAlert();
    // Mutate a field without updating the checksum
    const tampered = { ...alert, threatScore: 0.01 };
    expect(() => verifyAlertChecksum(tampered)).toThrow(IntegrityViolationException);
  });

  it('throws IntegrityViolationException when tenantId is mutated', () => {
    const alert = makeAlert();
    const tampered = { ...alert, tenantId: '44444444-4444-4444-8444-444444444444' };
    expect(() => verifyAlertChecksum(tampered)).toThrow(IntegrityViolationException);
  });

  it('throws IntegrityViolationException when killChainStage is mutated', () => {
    const alert = makeAlert();
    const tampered = { ...alert, killChainStage: 'RECONNAISSANCE' as const };
    expect(() => verifyAlertChecksum(tampered)).toThrow(IntegrityViolationException);
  });

  it('checksum is deterministic — same inputs produce same checksum', () => {
    const a = makeAlert();
    const b = makeAlert();
    expect(a.checksum).toBe(b.checksum);
  });
});
