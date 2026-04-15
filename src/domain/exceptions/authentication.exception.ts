/**
 * Thrown when authentication fails (invalid token, expired, revoked, etc.).
 * Maps to HTTP 401.
 */
export class AuthenticationException extends Error {
  readonly httpStatus = 401;
  readonly retryable = false;

  constructor(
    public readonly errorCode: string,
    message?: string,
  ) {
    super(message ?? errorCode);
    this.name = 'AuthenticationException';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
