/**
 * Credential entity — holds a hashed password record associated with a user.
 * Pure domain object; zero framework imports.
 */
// WAR-GRADE DEFENSE: Phase 9 2027 Survival Design
// Abstract the Credential entity to support FIDO2 WebAuthn / Passkeys natively.
export type HashAlgorithm = 'bcrypt' | 'webauthn_es256' | 'webauthn_rs256';

export interface CredentialParams {
  hash?: string; // Optional for passkeys
  algorithm: HashAlgorithm;
  rounds?: number; // Optional for passkeys
  publicKey?: string; // FIDO2 Public Key
  credentialId?: string; // FIDO2 Credential ID
  signCount?: number; // FIDO2 signature count to prevent cloning
  createdAt?: Date;
  updatedAt?: Date;
}

export class Credential {
  readonly hash: string;
  readonly algorithm: HashAlgorithm;
  readonly rounds: number;
  readonly publicKey?: string;
  readonly credentialId?: string;
  readonly signCount?: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;

  constructor(params: CredentialParams) {
    this.hash = params.hash ?? '';
    this.algorithm = params.algorithm;
    this.rounds = params.rounds ?? 0;
    this.publicKey = params.publicKey;
    this.credentialId = params.credentialId;
    this.signCount = params.signCount;
    this.createdAt = params.createdAt ?? new Date();
    this.updatedAt = params.updatedAt ?? new Date();
  }

  isPasskey(): boolean {
    return this.algorithm.startsWith('webauthn');
  }

  /**
   * Returns true when the stored bcrypt rounds differ from the current target rounds,
   * indicating the credential should be rehashed on next successful login.
   */
  needsRehash(currentRounds: number): boolean {
    if (this.isPasskey()) return false;
    return this.rounds !== currentRounds;
  }
}
