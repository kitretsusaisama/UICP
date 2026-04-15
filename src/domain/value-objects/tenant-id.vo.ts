import { randomUUID } from 'crypto';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

const UUID_V4_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class TenantId {
  private constructor(private readonly value: string) {}

  static create(): TenantId {
    return new TenantId(randomUUID());
  }

  static from(value: string): TenantId {
    if (!UUID_V4_REGEX.test(value)) {
      throw new DomainException(DomainErrorCode.INVALID_TENANT_ID, `Invalid TenantId: ${value}`);
    }
    return new TenantId(value);
  }

  static fromOptional(value?: string): TenantId | undefined {
    if (value === undefined || value === null) return undefined;
    return TenantId.from(value);
  }

  equals(other: TenantId): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}
