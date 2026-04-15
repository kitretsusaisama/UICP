import * as fc from 'fast-check';
import { Email } from './email.vo';
import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

/**
 * Unit tests and property tests for Email value object invariants.
 * Validates: Requirements 2.4
 */

const DISPOSABLE_DOMAINS_FILTER = new Set([
  'mailinator.com',
  'guerrillamail.com',
  'tempmail.com',
  'throwaway.email',
  'yopmail.com',
  'sharklasers.com',
  'guerrillamailblock.com',
  'grr.la',
  'guerrillamail.info',
  'spam4.me',
]);

describe('Email value object', () => {
  describe('valid email', () => {
    it('accepts a valid email and normalizes to lowercase', () => {
      const email = Email.create('User@Example.COM');
      expect(email.getValue()).toBe('user@example.com');
    });

    it('trims whitespace before validating', () => {
      const email = Email.create('  user@example.com  ');
      expect(email.getValue()).toBe('user@example.com');
    });
  });

  describe('invalid RFC format', () => {
    it('throws INVALID_EMAIL for missing @', () => {
      expect(() => Email.create('notanemail')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_EMAIL }),
      );
    });

    it('throws INVALID_EMAIL for missing domain', () => {
      expect(() => Email.create('user@')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_EMAIL }),
      );
    });

    it('throws INVALID_EMAIL for missing local part', () => {
      expect(() => Email.create('@example.com')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_EMAIL }),
      );
    });

    it('throws INVALID_EMAIL for domain without TLD', () => {
      expect(() => Email.create('user@localhost')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_EMAIL }),
      );
    });

    it('throws INVALID_EMAIL for plain string with no structure', () => {
      expect(() => Email.create('plainaddress')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_EMAIL }),
      );
    });

    it('throws a DomainException instance', () => {
      expect(() => Email.create('bad-email')).toThrow(DomainException);
    });
  });

  describe('email exceeding 320 characters', () => {
    it('throws INVALID_EMAIL when email is longer than 320 chars', () => {
      // local(310) + @ + example.com(11) = 322 chars
      const local = 'a'.repeat(310);
      const longEmail = `${local}@example.com`;
      expect(longEmail.length).toBeGreaterThan(320);
      expect(() => Email.create(longEmail)).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.INVALID_EMAIL }),
      );
    });

    it('accepts email at exactly 320 characters', () => {
      // local(308) + @ + example.com(11) = 320
      const local = 'a'.repeat(308);
      const email = Email.create(`${local}@example.com`);
      expect(email.getValue()).toBe(`${local}@example.com`);
    });
  });

  describe('disposable email domain', () => {
    it('throws DISPOSABLE_EMAIL_DOMAIN for mailinator.com', () => {
      expect(() => Email.create('user@mailinator.com')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.DISPOSABLE_EMAIL_DOMAIN }),
      );
    });

    it('throws DISPOSABLE_EMAIL_DOMAIN for guerrillamail.com', () => {
      expect(() => Email.create('user@guerrillamail.com')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.DISPOSABLE_EMAIL_DOMAIN }),
      );
    });

    it('throws DISPOSABLE_EMAIL_DOMAIN for yopmail.com', () => {
      expect(() => Email.create('user@yopmail.com')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.DISPOSABLE_EMAIL_DOMAIN }),
      );
    });

    it('throws DISPOSABLE_EMAIL_DOMAIN for tempmail.com', () => {
      expect(() => Email.create('user@tempmail.com')).toThrow(
        expect.objectContaining({ errorCode: DomainErrorCode.DISPOSABLE_EMAIL_DOMAIN }),
      );
    });
  });

  describe('Property 7 — normalization roundtrip', () => {
    it('Email.create(valid) always produces a normalized lowercase value', () => {
      /**
       * **Validates: Requirements 2.4**
       *
       * For any valid email address from a non-disposable domain,
       * Email.create(raw).getValue() equals raw.toLowerCase().trim()
       */
      fc.assert(
        fc.property(
          fc.emailAddress().filter((email) => {
            const domain = email.split('@')[1]!.toLowerCase();
            return !DISPOSABLE_DOMAINS_FILTER.has(domain);
          }),
          (email) => {
            const result = Email.create(email);
            expect(result.getValue()).toBe(email.toLowerCase().trim());
          },
        ),
      );
    });
  });
});
