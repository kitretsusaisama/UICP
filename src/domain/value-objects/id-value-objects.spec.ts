import { TenantId } from './tenant-id.vo';
import { UserId } from './user-id.vo';
import { IdentityId } from './identity-id.vo';
import { SessionId } from './session-id.vo';
import { TokenId } from './token-id.vo';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

/**
 * Unit tests for ID value object invariants.
 * Validates: Requirements 2.4
 */

const VALID_UUID = '550e8400-e29b-41d4-a716-446655440000';
const INVALID_INPUTS = [
  'not-a-uuid',
  '12345',
  '',
  'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
  // UUID v1 (not v4)
  '550e8400-e29b-11d4-a716-446655440000',
  // UUID v4 with wrong variant
  '550e8400-e29b-41d4-c716-446655440000',
];

describe('TenantId value object', () => {
  it('accepts a valid UUID v4', () => {
    const id = TenantId.from(VALID_UUID);
    expect(id.toString()).toBe(VALID_UUID);
  });

  it('generates a new valid UUID via create()', () => {
    const id = TenantId.create();
    expect(id.toString()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it.each(INVALID_INPUTS)('throws INVALID_TENANT_ID for "%s"', (input) => {
    expect(() => TenantId.from(input)).toThrow(
      expect.objectContaining({ errorCode: DomainErrorCode.INVALID_TENANT_ID }),
    );
  });

  it('throws a DomainException instance', () => {
    expect(() => TenantId.from('bad')).toThrow(DomainException);
  });
});

describe('UserId value object', () => {
  it('accepts a valid UUID v4', () => {
    const id = UserId.from(VALID_UUID);
    expect(id.toString()).toBe(VALID_UUID);
  });

  it('generates a new valid UUID via create()', () => {
    const id = UserId.create();
    expect(id.toString()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it.each(INVALID_INPUTS)('throws INVALID_USER_ID for "%s"', (input) => {
    expect(() => UserId.from(input)).toThrow(
      expect.objectContaining({ errorCode: DomainErrorCode.INVALID_USER_ID }),
    );
  });

  it('throws a DomainException instance', () => {
    expect(() => UserId.from('bad')).toThrow(DomainException);
  });
});

describe('IdentityId value object', () => {
  it('accepts a valid UUID v4', () => {
    const id = IdentityId.from(VALID_UUID);
    expect(id.toString()).toBe(VALID_UUID);
  });

  it('generates a new valid UUID via create()', () => {
    const id = IdentityId.create();
    expect(id.toString()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it.each(INVALID_INPUTS)('throws INVALID_IDENTITY_ID for "%s"', (input) => {
    expect(() => IdentityId.from(input)).toThrow(
      expect.objectContaining({ errorCode: DomainErrorCode.INVALID_IDENTITY_ID }),
    );
  });

  it('throws a DomainException instance', () => {
    expect(() => IdentityId.from('bad')).toThrow(DomainException);
  });
});

describe('SessionId value object', () => {
  it('accepts a valid UUID v4', () => {
    const id = SessionId.from(VALID_UUID);
    expect(id.toString()).toBe(VALID_UUID);
  });

  it('generates a new valid UUID via create()', () => {
    const id = SessionId.create();
    expect(id.toString()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it.each(INVALID_INPUTS)('throws INVALID_SESSION_ID for "%s"', (input) => {
    expect(() => SessionId.from(input)).toThrow(
      expect.objectContaining({ errorCode: DomainErrorCode.INVALID_SESSION_ID }),
    );
  });

  it('throws a DomainException instance', () => {
    expect(() => SessionId.from('bad')).toThrow(DomainException);
  });
});

describe('TokenId value object', () => {
  it('accepts a valid UUID v4', () => {
    const id = TokenId.from(VALID_UUID);
    expect(id.toString()).toBe(VALID_UUID);
  });

  it('generates a new valid UUID via create()', () => {
    const id = TokenId.create();
    expect(id.toString()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it.each(INVALID_INPUTS)('throws INVALID_TOKEN_ID for "%s"', (input) => {
    expect(() => TokenId.from(input)).toThrow(
      expect.objectContaining({ errorCode: DomainErrorCode.INVALID_TOKEN_ID }),
    );
  });

  it('throws a DomainException instance', () => {
    expect(() => TokenId.from('bad')).toThrow(DomainException);
  });
});
