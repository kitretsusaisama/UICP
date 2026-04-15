import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

/**
 * E.164 format: + followed by 1–3 digit country code and 4–14 subscriber digits.
 * Total digits after + must be between 8 and 15.
 */
const E164_REGEX = /^\+[1-9]\d{7,14}$/;

export class PhoneNumber {
  private constructor(private readonly value: string) {}

  static create(raw: string): PhoneNumber {
    if (typeof raw !== 'string') {
      throw new DomainException(
        DomainErrorCode.INVALID_PHONE_NUMBER,
        'Phone number must be a string',
      );
    }

    const normalized = raw.trim();

    if (!E164_REGEX.test(normalized)) {
      throw new DomainException(
        DomainErrorCode.INVALID_PHONE_NUMBER,
        `Phone number does not conform to E.164 format: ${normalized}`,
      );
    }

    // Verify digit count (8–15 digits after the +)
    const digits = normalized.slice(1);
    if (digits.length < 8 || digits.length > 15) {
      throw new DomainException(
        DomainErrorCode.INVALID_PHONE_NUMBER,
        `Phone number must have 8–15 digits after the + prefix, got ${digits.length}`,
      );
    }

    return new PhoneNumber(normalized);
  }

  getValue(): string {
    return this.value;
  }

  /**
   * Returns the country code portion (1–3 digits after the +).
   * Uses a simple heuristic: checks 1, 2, and 3-digit prefixes against known ranges.
   * For production use, replace with a proper libphonenumber-based lookup.
   */
  getCountryCode(): string {
    const digits = this.value.slice(1);
    // 3-digit country codes (e.g. +1 is US/CA, but we check longer ones first)
    // This is a simplified extraction — returns the leading digits up to 3
    if (digits.length >= 3) {
      const threeDigit = digits.slice(0, 3);
      // Known 3-digit country codes start with 2, 3, 5, 6, 7, 8, 9
      if (['210', '211', '212', '213', '216', '218', '220', '221', '222', '223', '224',
           '225', '226', '227', '228', '229', '230', '231', '232', '233', '234', '235',
           '236', '237', '238', '239', '240', '241', '242', '243', '244', '245', '246',
           '247', '248', '249', '250', '251', '252', '253', '254', '255', '256', '257',
           '258', '260', '261', '262', '263', '264', '265', '266', '267', '268', '269',
           '290', '291', '297', '298', '299', '350', '351', '352', '353', '354', '355',
           '356', '357', '358', '359', '370', '371', '372', '373', '374', '375', '376',
           '377', '378', '380', '381', '382', '385', '386', '387', '389', '420', '421',
           '423', '500', '501', '502', '503', '504', '505', '506', '507', '508', '509',
           '590', '591', '592', '593', '594', '595', '596', '597', '598', '599', '670',
           '672', '673', '674', '675', '676', '677', '678', '679', '680', '681', '682',
           '683', '685', '686', '687', '688', '689', '690', '691', '692', '850', '852',
           '853', '855', '856', '880', '886', '960', '961', '962', '963', '964', '965',
           '966', '967', '968', '970', '971', '972', '973', '974', '975', '976', '977',
           '992', '993', '994', '995', '996', '998'].includes(threeDigit)) {
        return '+' + threeDigit;
      }
    }
    // 2-digit country codes
    if (digits.length >= 2) {
      const twoDigit = digits.slice(0, 2);
      if (['20', '27', '30', '31', '32', '33', '34', '36', '39', '40', '41', '43',
           '44', '45', '46', '47', '48', '49', '51', '52', '53', '54', '55', '56',
           '57', '58', '60', '61', '62', '63', '64', '65', '66', '81', '82', '84',
           '86', '90', '91', '92', '93', '94', '95', '98'].includes(twoDigit)) {
        return '+' + twoDigit;
      }
    }
    // Default: 1-digit country code (e.g. +1 for NANP)
    return '+' + digits.slice(0, 1);
  }

  toString(): string {
    return this.value;
  }
}
