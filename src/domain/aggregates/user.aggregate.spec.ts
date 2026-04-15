import * as fc from 'fast-check';
import { User, UserStatus } from './user.aggregate';
import { TenantId } from '../value-objects/tenant-id.vo';
import { IdentityId } from '../value-objects/identity-id.vo';
import { Identity, IdentityType, toEncryptedValue } from '../entities/identity.entity';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';
import {
  UserCreatedEvent,
  UserActivatedEvent,
  UserSuspendedEvent,
  UserUnsuspendedEvent,
  UserDeletedEvent,
  IdentityLinkedEvent,
  IdentityVerifiedEvent,
  PasswordChangedEvent,
  UserDomainEvent,
} from '../events/user.events';

// ── Helpers ────────────────────────────────────────────────────────────────

const VALID_STATES: ReadonlySet<UserStatus> = new Set(['PENDING', 'ACTIVE', 'SUSPENDED', 'DELETED']);

/**
 * Build a standalone Identity that can be linked to a user.
 * Uses a unique hash per call to avoid IDENTITY_ALREADY_LINKED conflicts.
 */
function buildIdentity(
  tenantId: TenantId,
  type: IdentityType = 'EMAIL',
  valueHash = `hash-${Math.random()}`,
): Identity {
  return Identity.createEmail({
    id: IdentityId.create(),
    tenantId,
    userId: { toString: () => 'unused', equals: () => false } as any,
    valueEnc: toEncryptedValue('enc'),
    valueHash,
  });
}

/**
 * Build a fresh ACTIVE User (PENDING → verifyIdentity → ACTIVE).
 * This is the minimal setup needed to exercise suspend/unsuspend/delete.
 */
function buildActiveUser(): User {
  const tenantId = TenantId.create();
  const user = User.createWithEmail({
    email: { getValue: () => 'test@example.com', getDomain: () => 'example.com', toHmacInput: () => 'test@example.com', toString: () => 'test@example.com' } as any,
    tenantId,
    emailEnc: toEncryptedValue('enc-value'),
    emailHash: 'hash-value',
  });

  // Grab the identity that was linked during creation
  const identity = user.getIdentities()[0]!;

  // Manually reconstitute a verified version of the identity so we can call verifyIdentity
  // (the identity on the user is unverified; we need to verify it via the aggregate command)
  user.verifyIdentity(identity.id);

  return user;
}

/**
 * Build a fresh PENDING User (no verified identity yet).
 */
function buildPendingUser(): User {
  const tenantId = TenantId.create();
  return User.createWithEmail({
    email: { getValue: () => 'test@example.com', getDomain: () => 'example.com', toHmacInput: () => 'test@example.com', toString: () => 'test@example.com' } as any,
    tenantId,
    emailEnc: toEncryptedValue('enc-value'),
    emailHash: 'hash-value',
  });
}

// ── Command types ──────────────────────────────────────────────────────────

type Command = 'activate' | 'suspend' | 'unsuspend' | 'delete';

/**
 * Apply a command to a user, ignoring expected DomainExceptions for invalid
 * transitions (those are the domain's way of enforcing the state machine).
 * Any unexpected error is re-thrown.
 */
function applyCommand(user: User, cmd: Command): void {
  try {
    switch (cmd) {
      case 'activate':
        user.activate();
        break;
      case 'suspend':
        user.suspend('test-reason');
        break;
      case 'unsuspend':
        user.unsuspend();
        break;
      case 'delete':
        user.delete();
        break;
    }
  } catch (err) {
    if (
      err instanceof DomainException &&
      (err.errorCode === DomainErrorCode.INVALID_STATUS_TRANSITION ||
        err.errorCode === DomainErrorCode.CANNOT_ACTIVATE_WITHOUT_VERIFIED_IDENTITY)
    ) {
      // Expected: domain rejects the transition — state must remain unchanged
      return;
    }
    throw err;
  }
}

// ── Property Tests ─────────────────────────────────────────────────────────

/**
 * Property 1: User state machine never reaches an invalid transition
 *
 * **Validates: Requirements 3.5, 3.6, 3.7**
 *
 * For any arbitrary sequence of commands applied to a User aggregate:
 * 1. The resulting status is always one of {PENDING, ACTIVE, SUSPENDED, DELETED}
 * 2. Once DELETED, no further state transitions are possible (DELETED is terminal)
 */
describe('User aggregate — Property 1: state machine invariants', () => {
  const commandArb = fc.constantFrom<Command>('activate', 'suspend', 'unsuspend', 'delete');
  const commandSequenceArb = fc.array(commandArb, { minLength: 1, maxLength: 20 });

  describe('starting from ACTIVE state', () => {
    it('state is always one of {PENDING, ACTIVE, SUSPENDED, DELETED} after any command sequence', () => {
      /**
       * **Validates: Requirements 3.5, 3.6, 3.7**
       */
      fc.assert(
        fc.property(commandSequenceArb, (commands) => {
          const user = buildActiveUser();

          for (const cmd of commands) {
            applyCommand(user, cmd);
            expect(VALID_STATES).toContain(user.getStatus());
          }
        }),
      );
    });

    it('DELETED is terminal — no command can change state once DELETED', () => {
      /**
       * **Validates: Requirements 3.5, 3.6, 3.7**
       */
      fc.assert(
        fc.property(commandSequenceArb, commandSequenceArb, (preDelete, postDelete) => {
          const user = buildActiveUser();

          // Apply commands until deleted or sequence exhausted
          for (const cmd of preDelete) {
            applyCommand(user, cmd);
          }

          // Force deletion
          if (user.getStatus() !== 'DELETED') {
            user.delete();
          }

          expect(user.getStatus()).toBe('DELETED');

          // Apply more commands — state must remain DELETED
          for (const cmd of postDelete) {
            applyCommand(user, cmd);
            expect(user.getStatus()).toBe('DELETED');
          }
        }),
      );
    });
  });

  describe('starting from PENDING state', () => {
    it('state is always one of {PENDING, ACTIVE, SUSPENDED, DELETED} after any command sequence', () => {
      /**
       * **Validates: Requirements 3.5, 3.6, 3.7**
       */
      fc.assert(
        fc.property(commandSequenceArb, (commands) => {
          const user = buildPendingUser();

          for (const cmd of commands) {
            applyCommand(user, cmd);
            expect(VALID_STATES).toContain(user.getStatus());
          }
        }),
      );
    });
  });

  describe('specific transition rules', () => {
    it('ACTIVE → SUSPENDED → ACTIVE cycle is always valid', () => {
      const user = buildActiveUser();
      expect(user.getStatus()).toBe('ACTIVE');

      user.suspend('reason');
      expect(user.getStatus()).toBe('SUSPENDED');

      user.unsuspend();
      expect(user.getStatus()).toBe('ACTIVE');
    });

    it('ACTIVE → DELETED is valid and terminal', () => {
      const user = buildActiveUser();
      user.delete();
      expect(user.getStatus()).toBe('DELETED');

      expect(() => user.delete()).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION }),
      );
      expect(() => user.suspend('reason')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION }),
      );
      expect(() => user.unsuspend()).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION }),
      );
    });

    it('SUSPENDED → DELETED is valid and terminal', () => {
      const user = buildActiveUser();
      user.suspend('reason');
      user.delete();
      expect(user.getStatus()).toBe('DELETED');
    });

    it('PENDING cannot be suspended directly', () => {
      const user = buildPendingUser();
      expect(() => user.suspend('reason')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION }),
      );
      expect(user.getStatus()).toBe('PENDING');
    });

    it('PENDING cannot be unsuspended', () => {
      const user = buildPendingUser();
      expect(() => user.unsuspend()).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION }),
      );
      expect(user.getStatus()).toBe('PENDING');
    });
  });
});

// ── Property 18: fromEvents round-trip ────────────────────────────────────

/**
 * Helpers for building valid event sequences that respect the state machine.
 *
 * The state machine is:
 *   PENDING ──[IdentityVerified + auto-activate]──► ACTIVE
 *   ACTIVE  ──[UserSuspended]────────────────────► SUSPENDED
 *   SUSPENDED ──[UserUnsuspended]────────────────► ACTIVE
 *   ACTIVE | SUSPENDED ──[UserDeleted]───────────► DELETED (terminal)
 */

/** Lifecycle step that can be appended after ACTIVE state. */
type LifecycleStep =
  | { kind: 'suspend' }
  | { kind: 'unsuspend' }   // only valid after suspend
  | { kind: 'delete' };

/**
 * Build a minimal valid event sequence starting from UserCreated.
 * Returns both the events array and the expected final status.
 */
function buildEventSequence(
  userId: string,
  tenantId: string,
  identityId: string,
  steps: LifecycleStep[],
): { events: UserDomainEvent[]; expectedStatus: UserStatus } {
  const now = new Date('2024-01-01T00:00:00.000Z').toISOString();
  let seq = 1;

  const events: UserDomainEvent[] = [
    new UserCreatedEvent({ userId, tenantId, createdAt: now }, seq++),
    new IdentityLinkedEvent({ identityId, type: 'EMAIL', userId }, tenantId, seq++),
    new IdentityVerifiedEvent({ identityId, type: 'EMAIL', verifiedAt: now }, userId, tenantId, seq++),
    new UserActivatedEvent({ userId, activatedAt: now }, tenantId, seq++),
  ];

  let status: UserStatus = 'ACTIVE';

  for (const step of steps) {
    if (status === 'DELETED') break; // terminal — ignore further steps

    if (step.kind === 'suspend' && status === 'ACTIVE') {
      events.push(new UserSuspendedEvent({ userId, reason: 'test' }, tenantId, seq++));
      status = 'SUSPENDED';
    } else if (step.kind === 'unsuspend' && status === 'SUSPENDED') {
      events.push(new UserUnsuspendedEvent({ userId }, tenantId, seq++));
      status = 'ACTIVE';
    } else if (step.kind === 'delete' && (status === 'ACTIVE' || status === 'SUSPENDED')) {
      events.push(new UserDeletedEvent({ userId, deletedAt: now }, tenantId, seq++));
      status = 'DELETED';
    }
    // Invalid transitions are simply skipped — they would not appear in a real event store
  }

  return { events, expectedStatus: status };
}

/**
 * Property 18: Events replayed in aggregate_seq order always reconstruct the same aggregate state
 *
 * **Validates: Requirements 2.1, 6.6**
 */
describe('User aggregate — Property 18: fromEvents round-trip (event ordering)', () => {
  // Fixed UUIDs for deterministic event construction
  const USER_ID = 'a1b2c3d4-e5f6-4789-8abc-def012345678';
  const TENANT_ID = 'b2c3d4e5-f6a7-4890-9bcd-ef0123456789';
  const IDENTITY_ID = 'c3d4e5f6-a7b8-4901-abcd-f01234567890';

  const stepArb = fc.constantFrom<LifecycleStep>(
    { kind: 'suspend' },
    { kind: 'unsuspend' },
    { kind: 'delete' },
  );
  const stepsArb = fc.array(stepArb, { minLength: 0, maxLength: 10 });

  it('fromEvents(events).getStatus() always matches the expected final state', () => {
    /**
     * **Validates: Requirements 2.1, 6.6**
     */
    fc.assert(
      fc.property(stepsArb, (steps) => {
        const { events, expectedStatus } = buildEventSequence(USER_ID, TENANT_ID, IDENTITY_ID, steps);
        const user = User.fromEvents(events);
        expect(user.getStatus()).toBe(expectedStatus);
      }),
    );
  });

  it('replaying the same events twice always produces identical status (determinism)', () => {
    /**
     * **Validates: Requirements 2.1, 6.6**
     */
    fc.assert(
      fc.property(stepsArb, (steps) => {
        const { events } = buildEventSequence(USER_ID, TENANT_ID, IDENTITY_ID, steps);

        const user1 = User.fromEvents(events);
        const user2 = User.fromEvents(events);

        expect(user1.getStatus()).toBe(user2.getStatus());
      }),
    );
  });

  it('event ordering is respected — status after full sequence matches last status-changing event', () => {
    /**
     * **Validates: Requirements 2.1, 6.6**
     */
    // Explicit sequence: ACTIVE → SUSPENDED → ACTIVE → DELETED
    const { events, expectedStatus } = buildEventSequence(USER_ID, TENANT_ID, IDENTITY_ID, [
      { kind: 'suspend' },
      { kind: 'unsuspend' },
      { kind: 'delete' },
    ]);

    const user = User.fromEvents(events);
    expect(user.getStatus()).toBe('DELETED');
    expect(expectedStatus).toBe('DELETED');
  });

  it('PENDING state is preserved when no activation events follow creation', () => {
    /**
     * **Validates: Requirements 2.1, 6.6**
     */
    const userId = USER_ID;
    const tenantId = TENANT_ID;
    const identityId = IDENTITY_ID;
    const now = new Date('2024-01-01T00:00:00.000Z').toISOString();

    // Only UserCreated + IdentityLinked — no IdentityVerified/UserActivated
    const events: UserDomainEvent[] = [
      new UserCreatedEvent({ userId, tenantId, createdAt: now }, 1),
      new IdentityLinkedEvent({ identityId, type: 'EMAIL', userId }, tenantId, 2),
    ];

    const user = User.fromEvents(events);
    expect(user.getStatus()).toBe('PENDING');
  });

  it('PasswordChanged events do not affect status during replay', () => {
    /**
     * **Validates: Requirements 2.1, 6.6**
     */
    const userId = USER_ID;
    const tenantId = TENANT_ID;
    const identityId = IDENTITY_ID;
    const now = new Date('2024-01-01T00:00:00.000Z').toISOString();

    const events: UserDomainEvent[] = [
      new UserCreatedEvent({ userId, tenantId, createdAt: now }, 1),
      new IdentityLinkedEvent({ identityId, type: 'EMAIL', userId }, tenantId, 2),
      new IdentityVerifiedEvent({ identityId, type: 'EMAIL', verifiedAt: now }, userId, tenantId, 3),
      new UserActivatedEvent({ userId, activatedAt: now }, tenantId, 4),
      new PasswordChangedEvent({ userId, algorithm: 'argon2id', changedAt: now }, tenantId, 5),
    ];

    const user = User.fromEvents(events);
    expect(user.getStatus()).toBe('ACTIVE');
  });
});

// ── Unit Tests: Task 3.3 — User aggregate invariants ──────────────────────

/**
 * Unit tests for User aggregate invariants.
 * Implements: Req 2, Req 3
 */
describe('User aggregate — invariant unit tests', () => {
  // ── activate() ────────────────────────────────────────────────────────────

  describe('activate()', () => {
    it('throws CANNOT_ACTIVATE_WITHOUT_VERIFIED_IDENTITY when no verified identity exists', () => {
      // PENDING user with an unverified identity (default state after createWithEmail)
      const user = buildPendingUser();

      expect(() => user.activate()).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.CANNOT_ACTIVATE_WITHOUT_VERIFIED_IDENTITY,
        }),
      );
      expect(user.getStatus()).toBe('PENDING');
    });

    it('throws INVALID_STATUS_TRANSITION when user is ACTIVE', () => {
      const user = buildActiveUser();
      expect(user.getStatus()).toBe('ACTIVE');

      expect(() => user.activate()).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION,
        }),
      );
      expect(user.getStatus()).toBe('ACTIVE');
    });

    it('throws INVALID_STATUS_TRANSITION when user is SUSPENDED', () => {
      const user = buildActiveUser();
      user.suspend('test');
      expect(user.getStatus()).toBe('SUSPENDED');

      expect(() => user.activate()).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION,
        }),
      );
      expect(user.getStatus()).toBe('SUSPENDED');
    });

    it('throws INVALID_STATUS_TRANSITION when user is DELETED', () => {
      const user = buildActiveUser();
      user.delete();
      expect(user.getStatus()).toBe('DELETED');

      expect(() => user.activate()).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION,
        }),
      );
      expect(user.getStatus()).toBe('DELETED');
    });
  });

  // ── suspend() ─────────────────────────────────────────────────────────────

  describe('suspend()', () => {
    it('throws INVALID_STATUS_TRANSITION when user is PENDING', () => {
      const user = buildPendingUser();

      expect(() => user.suspend('reason')).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION,
        }),
      );
      expect(user.getStatus()).toBe('PENDING');
    });

    it('throws INVALID_STATUS_TRANSITION when user is already SUSPENDED', () => {
      const user = buildActiveUser();
      user.suspend('first');

      expect(() => user.suspend('second')).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION,
        }),
      );
      expect(user.getStatus()).toBe('SUSPENDED');
    });

    it('throws INVALID_STATUS_TRANSITION when user is DELETED', () => {
      const user = buildActiveUser();
      user.delete();

      expect(() => user.suspend('reason')).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION,
        }),
      );
      expect(user.getStatus()).toBe('DELETED');
    });
  });

  // ── delete() ──────────────────────────────────────────────────────────────

  describe('delete()', () => {
    it('throws INVALID_STATUS_TRANSITION when user is already DELETED', () => {
      const user = buildActiveUser();
      user.delete();
      expect(user.getStatus()).toBe('DELETED');

      expect(() => user.delete()).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.INVALID_STATUS_TRANSITION,
        }),
      );
      expect(user.getStatus()).toBe('DELETED');
    });

    it('can delete a SUSPENDED user', () => {
      const user = buildActiveUser();
      user.suspend('reason');
      user.delete();
      expect(user.getStatus()).toBe('DELETED');
    });

    it('can delete a PENDING user', () => {
      const user = buildPendingUser();
      user.delete();
      expect(user.getStatus()).toBe('DELETED');
    });
  });

  // ── linkIdentity() ────────────────────────────────────────────────────────

  describe('linkIdentity()', () => {
    it('throws MAX_IDENTITIES_PER_TYPE_EXCEEDED when linking a 4th identity of the same type', () => {
      const tenantId = TenantId.create();
      const user = User.createWithEmail({
        email: { getValue: () => 'a@example.com', getDomain: () => 'example.com', toHmacInput: () => 'a@example.com', toString: () => 'a@example.com' } as any,
        tenantId,
        emailEnc: toEncryptedValue('enc'),
        emailHash: 'hash-original',
      });

      // The user already has 1 EMAIL identity from creation; link 2 more to reach the limit of 3
      user.linkIdentity(buildIdentity(tenantId, 'EMAIL', 'hash-2'));
      user.linkIdentity(buildIdentity(tenantId, 'EMAIL', 'hash-3'));

      // Now at 3 EMAIL identities — the next one must be rejected
      expect(() => user.linkIdentity(buildIdentity(tenantId, 'EMAIL', 'hash-4'))).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.MAX_IDENTITIES_PER_TYPE_EXCEEDED,
        }),
      );
    });

    it('allows linking up to 3 identities of the same type', () => {
      const tenantId = TenantId.create();
      const user = User.createWithEmail({
        email: { getValue: () => 'a@example.com', getDomain: () => 'example.com', toHmacInput: () => 'a@example.com', toString: () => 'a@example.com' } as any,
        tenantId,
        emailEnc: toEncryptedValue('enc'),
        emailHash: 'hash-original',
      });

      // Link 2 more EMAIL identities (total = 3, which is the max)
      expect(() => {
        user.linkIdentity(buildIdentity(tenantId, 'EMAIL', 'hash-2'));
        user.linkIdentity(buildIdentity(tenantId, 'EMAIL', 'hash-3'));
      }).not.toThrow();

      expect(user.getIdentities().filter((i) => i.getType() === 'EMAIL')).toHaveLength(3);
    });

    it('throws IDENTITY_ALREADY_LINKED when linking a duplicate valueHash of the same type', () => {
      const tenantId = TenantId.create();
      const user = User.createWithEmail({
        email: { getValue: () => 'a@example.com', getDomain: () => 'example.com', toHmacInput: () => 'a@example.com', toString: () => 'a@example.com' } as any,
        tenantId,
        emailEnc: toEncryptedValue('enc'),
        emailHash: 'duplicate-hash',
      });

      // Attempt to link another EMAIL identity with the same hash
      const duplicate = buildIdentity(tenantId, 'EMAIL', 'duplicate-hash');
      expect(() => user.linkIdentity(duplicate)).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.IDENTITY_ALREADY_LINKED,
        }),
      );
    });

    it('allows linking identities of different types with the same hash', () => {
      // Same hash but different type is NOT a duplicate
      const tenantId = TenantId.create();
      const user = User.createWithEmail({
        email: { getValue: () => 'a@example.com', getDomain: () => 'example.com', toHmacInput: () => 'a@example.com', toString: () => 'a@example.com' } as any,
        tenantId,
        emailEnc: toEncryptedValue('enc'),
        emailHash: 'shared-hash',
      });

      // PHONE identity with the same hash value — should be allowed
      const phoneIdentity = Identity.createEmail({
        id: IdentityId.create(),
        tenantId,
        userId: { toString: () => 'unused', equals: () => false } as any,
        valueEnc: toEncryptedValue('enc'),
        valueHash: 'shared-hash',
      });

      // Override type via reconstitute to simulate a PHONE identity
      const phoneAsPhone = Identity.reconstitute({
        id: IdentityId.create(),
        tenantId,
        userId: { toString: () => 'unused', equals: () => false } as any,
        type: 'PHONE',
        valueEnc: toEncryptedValue('enc'),
        valueHash: 'shared-hash',
        verified: false,
        createdAt: new Date(),
      });

      expect(() => user.linkIdentity(phoneAsPhone)).not.toThrow();
    });
  });

  // ── verifyIdentity() ──────────────────────────────────────────────────────

  describe('verifyIdentity()', () => {
    it('throws IDENTITY_NOT_FOUND when the identityId does not belong to the user', () => {
      const user = buildPendingUser();
      const unknownId = IdentityId.create();

      expect(() => user.verifyIdentity(unknownId)).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.IDENTITY_NOT_FOUND,
        }),
      );
    });

    it('verifies a known identity and auto-activates the user when PENDING', () => {
      const user = buildPendingUser();
      const identity = user.getIdentities()[0]!;

      expect(user.getStatus()).toBe('PENDING');
      user.verifyIdentity(identity.id);
      expect(user.getStatus()).toBe('ACTIVE');
      expect(identity.isVerified()).toBe(true);
    });

    it('throws IDENTITY_ALREADY_VERIFIED when verifying an already-verified identity', () => {
      const user = buildPendingUser();
      const identity = user.getIdentities()[0]!;

      user.verifyIdentity(identity.id); // first verify — succeeds and activates

      expect(() => user.verifyIdentity(identity.id)).toThrow(
        expect.objectContaining({
          errorCode: DomainErrorCode.IDENTITY_ALREADY_VERIFIED,
        }),
      );
    });

    it('does not auto-activate when user is already ACTIVE', () => {
      const tenantId = TenantId.create();
      const user = User.createWithEmail({
        email: { getValue: () => 'a@example.com', getDomain: () => 'example.com', toHmacInput: () => 'a@example.com', toString: () => 'a@example.com' } as any,
        tenantId,
        emailEnc: toEncryptedValue('enc'),
        emailHash: 'hash-1',
      });

      // Activate via first identity
      const firstIdentity = user.getIdentities()[0]!;
      user.verifyIdentity(firstIdentity.id);
      expect(user.getStatus()).toBe('ACTIVE');

      // Link a second unverified identity
      const secondIdentity = Identity.reconstitute({
        id: IdentityId.create(),
        tenantId,
        userId: user.getId(),
        type: 'PHONE',
        valueEnc: toEncryptedValue('enc'),
        valueHash: 'hash-phone',
        verified: false,
        createdAt: new Date(),
      });
      user.linkIdentity(secondIdentity);

      // Verifying the second identity should not throw and user stays ACTIVE
      expect(() => user.verifyIdentity(secondIdentity.id)).not.toThrow();
      expect(user.getStatus()).toBe('ACTIVE');
    });
  });
});
