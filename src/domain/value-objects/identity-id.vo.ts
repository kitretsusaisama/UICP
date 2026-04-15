import { randomUUID } from 'crypto';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

const UUID_V4_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class IdentityId {
  private constructor(private readonly value: string) {}

  static create(): IdentityId {
    return new IdentityId(randomUUID());
  }

  static from(value: string): IdentityId {
    if (!UUID_V4_REGEX.test(value)) {
      throw new DomainException(
        DomainErrorCode.INVALID_IDENTITY_ID,
        `Invalid IdentityId: ${value}`,
      );
    }
    return new IdentityId(value);
  }

  static fromOptional(value?: string): IdentityId | undefined {
    if (value === undefined || value === null) return undefined;
    return IdentityId.from(value);
  }

  equals(other: IdentityId): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}
