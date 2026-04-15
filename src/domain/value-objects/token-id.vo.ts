import { randomUUID } from 'crypto';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

const UUID_V4_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class TokenId {
  private constructor(private readonly value: string) {}

  /** Generate a new UUID v4 for use as a JWT `jti` claim. */
  static create(): TokenId {
    return new TokenId(randomUUID());
  }

  static from(value: string): TokenId {
    if (!UUID_V4_REGEX.test(value)) {
      throw new DomainException(DomainErrorCode.INVALID_TOKEN_ID, `Invalid TokenId: ${value}`);
    }
    return new TokenId(value);
  }

  static fromOptional(value?: string): TokenId | undefined {
    if (value === undefined || value === null) return undefined;
    return TokenId.from(value);
  }

  equals(other: TokenId): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}
