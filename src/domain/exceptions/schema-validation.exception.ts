/**
 * Thrown when a Zod schema validation fails.
 * Maps to HTTP 422 (Unprocessable Entity) per API design best practices.
 */
export class SchemaValidationException extends Error {
  readonly httpStatus = 422;
  readonly retryable = false;

  constructor(
    public readonly errors: Array<{ path: string; message: string; code: string }>,
    message?: string,
  ) {
    super(message ?? 'Request validation failed');
    this.name = 'SchemaValidationException';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
