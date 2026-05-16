/**
 * Auth Session State
 *
 * Lifecycle:
 *   STARTED ──[identity submitted]──► IDENTITY_VERIFIED
 *   STARTED ──[identity not found + auto-create]──► IDENTITY_PENDING
 *   IDENTITY_PENDING ──[identity verified]──► IDENTITY_VERIFIED
 *   IDENTITY_VERIFIED ──[MFA required]──► CHALLENGED
 *   CHALLENGED ──[challenge passed]──► AUTHENTICATED
 *   IDENTITY_VERIFIED ──[no MFA needed]──► AUTHENTICATED
 *   AUTHENTICATED ──[profile incomplete]──► PROFILE_REQUIRED
 *   PROFILE_REQUIRED ──[profile completed]──► AUTHENTICATED
 *   ANY ──[risk threshold exceeded]──► BLOCKED
 *   ANY ──[timeout]──► EXPIRED
 */
export enum AuthState {
  /** Initial state - session created, waiting for identity */
  STARTED = 'STARTED',

  /** Identity submitted - pending verification (e.g., email sent) */
  IDENTITY_PENDING = 'IDENTITY_PENDING',

  /** Identity verified - either found or auto-created and verified */
  IDENTITY_VERIFIED = 'IDENTITY_VERIFIED',

  /** Waiting for challenge response (MFA, OTP, etc.) */
  CHALLENGED = 'CHALLENGED',

  /** Profile completion required before final tokens */
  PROFILE_REQUIRED = 'PROFILE_REQUIRED',

  /** Fully authenticated - tokens issued */
  AUTHENTICATED = 'AUTHENTICATED',

  /** Blocked due to risk or policy */
  BLOCKED = 'BLOCKED',

  /** Session expired due to timeout */
  EXPIRED = 'EXPIRED',

  /** User abandoned the flow */
  ABANDONED = 'ABANDONED',
}

/**
 * Check if state is terminal (no further transitions possible)
 */
export function isTerminalState(state: AuthState): boolean {
  return [
    AuthState.AUTHENTICATED,
    AuthState.BLOCKED,
    AuthState.EXPIRED,
    AuthState.ABANDONED,
  ].includes(state);
}

/**
 * Check if state allows continuation
 */
export function canContinue(state: AuthState): boolean {
  return !isTerminalState(state);
}