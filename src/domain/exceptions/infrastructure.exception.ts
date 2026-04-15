/**
 * Thrown when an infrastructure dependency (DB, Redis, external API) fails.
 * Maps to HTTP 503.
 */
export class InfrastructureException extends Error {
  readonly httpStatus = 503;
  readonly retryable = true;

  constructor(
    public readonly errorCode: string,
    message?: string,
  ) {
    super(message ?? errorCode);
    this.name = 'InfrastructureException';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
