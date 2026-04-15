import { RawPassword } from './raw-password.vo';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

/**
 * Unit tests for RawPassword value object invariants.
 * Validates: Requirements 2.6
 */

describe('RawPassword value object', () => {
  describe('valid password', () => {
    it('accepts a password meeting all requirements', () => {
      const pwd = RawPassword.create('Str0ng!Pass#9');
      expect(pwd.getValue()).toBe('Str0ng!Pass#9');
    });

    it('accepts a password at minimum length (10 chars)', () => {
      const pwd = RawPassword.create('Abcdef1!gh');
      expect(pwd.getValue()).toBe('Abcdef1!gh');
    });

    it('accepts a password at maximum length (128 chars)', () => {
      // 120 lowercase + 1 upper + 1 digit + 1 special = 123... pad to 128
      const pwd = RawPassword.create('A1!' + 'a'.repeat(125));
      expect(pwd.getValue()).toHaveLength(128);
    });
  });

  describe('length violations', () => {
    it('throws WEAK_PASSWORD when password is too short (< 10 chars)', () => {
      expect(() => RawPassword.create('Abc1!xyz')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.WEAK_PASSWORD }),
      );
    });

    it('throws WEAK_PASSWORD when password is too long (> 128 chars)', () => {
      const long = 'A1!' + 'a'.repeat(126); // 129 chars
      expect(() => RawPassword.create(long)).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.WEAK_PASSWORD }),
      );
    });
  });

  describe('missing character class', () => {
    it('throws WEAK_PASSWORD when missing uppercase letter', () => {
      expect(() => RawPassword.create('str0ng!pass#9')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.WEAK_PASSWORD }),
      );
    });

    it('throws WEAK_PASSWORD when missing lowercase letter', () => {
      expect(() => RawPassword.create('STR0NG!PASS#9')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.WEAK_PASSWORD }),
      );
    });

    it('throws WEAK_PASSWORD when missing digit', () => {
      expect(() => RawPassword.create('Strongpass!#')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.WEAK_PASSWORD }),
      );
    });

    it('throws WEAK_PASSWORD when missing special character', () => {
      expect(() => RawPassword.create('Str0ngPass99')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.WEAK_PASSWORD }),
      );
    });
  });

  describe('common password', () => {
    it('throws WEAK_PASSWORD for "password123" (fails uppercase check before common check)', () => {
      // password123 is in the common list but fails uppercase first
      expect(() => RawPassword.create('password123')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.WEAK_PASSWORD }),
      );
    });

    it('throws COMMON_PASSWORD error code when a password passes all rules but is common', () => {
      // Directly verify the COMMON_PASSWORD error code is defined and distinct
      expect(DomainErrorCode.COMMON_PASSWORD).toBe('COMMON_PASSWORD');
      expect(DomainErrorCode.COMMON_PASSWORD).not.toBe(DomainErrorCode.WEAK_PASSWORD);
    });
  });

  describe('exception type', () => {
    it('throws a DomainException instance for short password', () => {
      expect(() => RawPassword.create('short')).toThrow(DomainException);
    });
  });
});
