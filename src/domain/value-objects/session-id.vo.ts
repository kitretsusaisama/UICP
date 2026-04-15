import { randomUUID } from 'crypto';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

const UUID_V4_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class SessionId {
  private constructor(private readonly value: string) {}

  static create(): SessionId {
    return new SessionId(randomUUID());
  }

  static from(value: string): SessionId {
    if (!UUID_V4_REGEX.test(value)) {
      throw new DomainException(
        DomainErrorCode.INVALID_SESSION_ID,
        `Invalid SessionId: ${value}`,
      );
    }
    return new SessionId(value);
  }

  static fromOptional(value?: string): SessionId | undefined {
    if (value === undefined || value === null) return undefined;
    return SessionId.from(value);
  }

  equals(other: SessionId): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}
