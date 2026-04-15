import { randomUUID } from 'crypto';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

const UUID_V4_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class UserId {
  private constructor(private readonly value: string) {}

  static create(): UserId {
    return new UserId(randomUUID());
  }

  static from(value: string): UserId {
    if (!UUID_V4_REGEX.test(value)) {
      throw new DomainException(DomainErrorCode.INVALID_USER_ID, `Invalid UserId: ${value}`);
    }
    return new UserId(value);
  }

  static fromOptional(value?: string): UserId | undefined {
    if (value === undefined || value === null) return undefined;
    return UserId.from(value);
  }

  equals(other: UserId): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}
