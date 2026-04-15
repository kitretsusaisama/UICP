/**
 * Thrown when a Zod schema validation fails.
 * Maps to HTTP 400.
 */
export class SchemaValidationException extends Error {
  readonly httpStatus = 400;
  readonly retryable = false;

  constructor(
    public readonly errors: Array<{ path: string; message: string }>,
    message?: string,
  ) {
    super(message ?? 'Schema validation failed');
    this.name = 'SchemaValidationException';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
