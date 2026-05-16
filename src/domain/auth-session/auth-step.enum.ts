/**
 * Individual steps within an auth session
 * Used for tracking progress and resumability
 */
export enum AuthStep {
  /** Initial step - session created */
  INIT = 'INIT',

  /** Identity submitted (email/phone/OAuth) */
  IDENTITY = 'IDENTITY',

  /** Identity verification pending (OTP sent, magic link sent) */
  IDENTITY_VERIFICATION = 'IDENTITY_VERIFICATION',

  /** Identity verified (password verified, or auto-created) */
  IDENTITY_VERIFIED = 'IDENTITY_VERIFIED',

  /** MFA challenge required */
  CHALLENGE = 'CHALLENGE',

  /** Challenge passed */
  CHALLENGE_PASSED = 'CHALLENGE_PASSED',

  /** Profile completion */
  PROFILE = 'PROFILE',

  /** Profile completed */
  PROFILE_COMPLETE = 'PROFILE_COMPLETE',

  /** Tokens issued - auth flow complete */
  COMPLETE = 'COMPLETE',
}

/**
 * Get the step index for ordering
 */
export function getStepIndex(step: AuthStep): number {
  const stepOrder = [
    AuthStep.INIT,
    AuthStep.IDENTITY,
    AuthStep.IDENTITY_VERIFICATION,
    AuthStep.IDENTITY_VERIFIED,
    AuthStep.CHALLENGE,
    AuthStep.CHALLENGE_PASSED,
    AuthStep.PROFILE,
    AuthStep.PROFILE_COMPLETE,
    AuthStep.COMPLETE,
  ];
  return stepOrder.indexOf(step);
}

/**
 * Check if step is completed
 */
export function isStepCompleted(completedSteps: AuthStep[], step: AuthStep): boolean {
  const currentIndex = getStepIndex(step);
  return completedSteps.some((s) => getStepIndex(s) >= currentIndex);
}