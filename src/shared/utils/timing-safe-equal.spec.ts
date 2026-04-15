import { timingSafeEqual } from './timing-safe-equal';

describe('timingSafeEqual', () => {
  describe('equal strings', () => {
    it('returns true for identical strings', () => {
      expect(timingSafeEqual('hello', 'hello')).toBe(true);
    });

    it('returns true for empty strings', () => {
      expect(timingSafeEqual('', '')).toBe(true);
    });

    it('returns true for long identical strings', () => {
      const s = 'a'.repeat(1000);
      expect(timingSafeEqual(s, s)).toBe(true);
    });

    it('returns true for strings with special characters', () => {
      const s = '!@#$%^&*()_+-=[]{}|;\':",./<>?';
      expect(timingSafeEqual(s, s)).toBe(true);
    });

    it('returns true for unicode strings', () => {
      const s = '日本語テスト🔐';
      expect(timingSafeEqual(s, s)).toBe(true);
    });
  });

  describe('unequal strings', () => {
    it('returns false for different strings of same length', () => {
      expect(timingSafeEqual('hello', 'world')).toBe(false);
    });

    it('returns false for strings differing only in case', () => {
      expect(timingSafeEqual('Hello', 'hello')).toBe(false);
    });

    it('returns false for strings of different lengths', () => {
      expect(timingSafeEqual('hello', 'hello!')).toBe(false);
    });

    it('returns false when first string is empty', () => {
      expect(timingSafeEqual('', 'hello')).toBe(false);
    });

    it('returns false when second string is empty', () => {
      expect(timingSafeEqual('hello', '')).toBe(false);
    });

    it('returns false for OTP-like codes that differ by one digit', () => {
      expect(timingSafeEqual('123456', '123457')).toBe(false);
    });
  });
});
