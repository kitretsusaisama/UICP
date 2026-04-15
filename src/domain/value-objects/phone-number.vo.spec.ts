import { PhoneNumber } from './phone-number.vo';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

/**
 * Unit tests for PhoneNumber value object invariants.
 * Validates: Requirements 2.5
 */

describe('PhoneNumber value object', () => {
  describe('valid E.164 numbers', () => {
    it('accepts a valid US number', () => {
      const phone = PhoneNumber.create('+12025551234');
      expect(phone.getValue()).toBe('+12025551234');
    });

    it('accepts a valid UK number', () => {
      const phone = PhoneNumber.create('+447911123456');
      expect(phone.getValue()).toBe('+447911123456');
    });

    it('accepts minimum length E.164 (8 digits after +)', () => {
      const phone = PhoneNumber.create('+12345678');
      expect(phone.getValue()).toBe('+12345678');
    });

    it('accepts maximum length E.164 (15 digits after +)', () => {
      const phone = PhoneNumber.create('+123456789012345');
      expect(phone.getValue()).toBe('+123456789012345');
    });
  });

  describe('non-E.164 inputs', () => {
    it('throws INVALID_PHONE_NUMBER when missing + prefix', () => {
      expect(() => PhoneNumber.create('12025551234')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_PHONE_NUMBER }),
      );
    });

    it('throws INVALID_PHONE_NUMBER for too short (fewer than 8 digits after +)', () => {
      expect(() => PhoneNumber.create('+1234567')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_PHONE_NUMBER }),
      );
    });

    it('throws INVALID_PHONE_NUMBER for too long (more than 15 digits after +)', () => {
      expect(() => PhoneNumber.create('+1234567890123456')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_PHONE_NUMBER }),
      );
    });

    it('throws INVALID_PHONE_NUMBER when letters are present', () => {
      expect(() => PhoneNumber.create('+1800FLOWERS')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_PHONE_NUMBER }),
      );
    });

    it('throws INVALID_PHONE_NUMBER for number with spaces', () => {
      expect(() => PhoneNumber.create('+1 202 555 1234')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_PHONE_NUMBER }),
      );
    });

    it('throws INVALID_PHONE_NUMBER for number with dashes', () => {
      expect(() => PhoneNumber.create('+1-202-555-1234')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_PHONE_NUMBER }),
      );
    });

    it('throws INVALID_PHONE_NUMBER for empty string', () => {
      expect(() => PhoneNumber.create('')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_PHONE_NUMBER }),
      );
    });

    it('throws INVALID_PHONE_NUMBER when country code starts with 0', () => {
      // E.164 requires first digit after + to be 1-9
      expect(() => PhoneNumber.create('+02025551234')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_PHONE_NUMBER }),
      );
    });

    it('throws a DomainException instance', () => {
      expect(() => PhoneNumber.create('not-a-phone')).toThrow(DomainException);
    });
  });
});
