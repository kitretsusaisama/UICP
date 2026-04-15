/**
 * Credential entity — holds a hashed password record associated with a user.
 * Pure domain object; zero framework imports.
 */
export type HashAlgorithm = 'bcrypt';

export interface CredentialParams {
  hash: string;
  algorithm: HashAlgorithm;
  rounds: number;
  createdAt?: Date;
  updatedAt?: Date;
}

export class Credential {
  readonly hash: string;
  readonly algorithm: HashAlgorithm;
  readonly rounds: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;

  constructor(params: CredentialParams) {
    this.hash = params.hash;
    this.algorithm = params.algorithm;
    this.rounds = params.rounds;
    this.createdAt = params.createdAt ?? new Date();
    this.updatedAt = params.updatedAt ?? new Date();
  }

  /**
   * Returns true when the stored bcrypt rounds differ from the current target rounds,
   * indicating the credential should be rehashed on next successful login.
   */
  needsRehash(currentRounds: number): boolean {
    return this.rounds !== currentRounds;
  }
}
