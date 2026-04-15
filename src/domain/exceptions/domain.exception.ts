import { type DomainErrorCode } from './domain-error-codes';

export class DomainException extends Error {
  constructor(
    public readonly errorCode: DomainErrorCode,
    message?: string,
  ) {
    super(message ?? errorCode);
    this.name = 'DomainException';
    // Maintain proper prototype chain in transpiled ES5
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
