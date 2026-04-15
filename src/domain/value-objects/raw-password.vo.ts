import { DomainException } from '../exceptions/domain.exception';
import { DomainErrorCode } from '../exceptions/domain-error-codes';

const MIN_LENGTH = 10;
const MAX_LENGTH = 128;

const HAS_UPPERCASE = /[A-Z]/;
const HAS_LOWERCASE = /[a-z]/;
const HAS_DIGIT = /[0-9]/;
const HAS_SPECIAL = /[!@#$%^&*()\-_=+\[\]{};:'",.<>?/\\|`~]/;

/**
 * Representative subset of the top-10,000 most common passwords.
 * In production, load the full list from a file (e.g. SecLists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt).
 */
const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  'password',
  'password1',
  'password12',
  'password123',
  'password1234',
  'password12345',
  'password123456',
  '123456789',
  '1234567890',
  '12345678',
  '1234567',
  '123456',
  '12345',
  '1234',
  '123',
  'qwerty',
  'qwerty123',
  'qwertyuiop',
  'abc123',
  'abcdef',
  'abcdefgh',
  'letmein',
  'letmein1',
  'welcome',
  'welcome1',
  'monkey',
  'monkey1',
  'dragon',
  'dragon1',
  'master',
  'master1',
  'sunshine',
  'sunshine1',
  'princess',
  'princess1',
  'football',
  'football1',
  'baseball',
  'baseball1',
  'iloveyou',
  'iloveyou1',
  'trustno1',
  'superman',
  'superman1',
  'batman',
  'batman1',
  'shadow',
  'shadow1',
  'michael',
  'michael1',
  'jessica',
  'jessica1',
  'charlie',
  'charlie1',
  'donald',
  'donald1',
  'harley',
  'harley1',
  'ranger',
  'ranger1',
  'solo',
  'solo1',
  'passw0rd',
  'p@ssword',
  'p@ssw0rd',
  'pa$$word',
  'pa$$w0rd',
  'pass@word',
  'pass@w0rd',
  'pass1word',
  'pass1w0rd',
  'pass12word',
  'pass12w0rd',
  'pass123word',
  'pass123w0rd',
  'pass1234word',
  'pass1234w0rd',
  'pass12345word',
  'pass12345w0rd',
  'pass123456word',
  'pass123456w0rd',
  'pass1234567word',
  'pass1234567w0rd',
  'pass12345678word',
  'pass12345678w0rd',
  'pass123456789word',
  'pass123456789w0rd',
  'pass1234567890word',
  'pass1234567890w0rd',
  'admin',
  'admin1',
  'admin12',
  'admin123',
  'admin1234',
  'admin12345',
  'admin123456',
  'administrator',
  'administrator1',
  'root',
  'root1',
  'root12',
  'root123',
  'toor',
  'toor1',
  'toor12',
  'toor123',
  'test',
  'test1',
  'test12',
  'test123',
  'test1234',
  'test12345',
  'test123456',
  'testing',
  'testing1',
  'testing12',
  'testing123',
  'guest',
  'guest1',
  'guest12',
  'guest123',
  'user',
  'user1',
  'user12',
  'user123',
  'login',
  'login1',
  'login12',
  'login123',
  'changeme',
  'changeme1',
  'changeme12',
  'changeme123',
  'default',
  'default1',
  'default12',
  'default123',
  'secret',
  'secret1',
  'secret12',
  'secret123',
  'pass',
  'pass1',
  'pass12',
  'pass123',
  'pass1234',
  'pass12345',
  'pass123456',
  'hello',
  'hello1',
  'hello12',
  'hello123',
  'hello1234',
  'hello12345',
  'hello123456',
  'world',
  'world1',
  'world12',
  'world123',
  'helloworld',
  'helloworld1',
  'helloworld12',
  'helloworld123',
  'qazwsx',
  'qazwsxedc',
  'zxcvbn',
  'zxcvbnm',
  'asdfgh',
  'asdfghjkl',
  'asdf1234',
  '1q2w3e4r',
  '1q2w3e4r5t',
  '1q2w3e',
  'q1w2e3r4',
  'q1w2e3r4t5',
  'q1w2e3',
  'aaaaaa',
  'aaaaaaa',
  'aaaaaaaa',
  'aaaaaaaaa',
  'aaaaaaaaaa',
  '111111',
  '1111111',
  '11111111',
  '111111111',
  '1111111111',
  '000000',
  '0000000',
  '00000000',
  '000000000',
  '0000000000',
  '999999',
  '9999999',
  '99999999',
  '999999999',
  '9999999999',
  'abc',
  'abcd',
  'abcde',
  'abcdef',
  'abcdefg',
  'abcdefgh',
  'abcdefghi',
  'abcdefghij',
  'abcdefghijk',
  'abcdefghijkl',
  'abcdefghijklm',
  'abcdefghijklmn',
  'abcdefghijklmno',
  'abcdefghijklmnop',
  'abcdefghijklmnopq',
  'abcdefghijklmnopqr',
  'abcdefghijklmnopqrs',
  'abcdefghijklmnopqrst',
  'abcdefghijklmnopqrstu',
  'abcdefghijklmnopqrstuv',
  'abcdefghijklmnopqrstuvw',
  'abcdefghijklmnopqrstuvwx',
  'abcdefghijklmnopqrstuvwxy',
  'abcdefghijklmnopqrstuvwxyz',
]);

export class RawPassword {
  private constructor(private readonly value: string) {}

  static create(raw: string): RawPassword {
    if (typeof raw !== 'string') {
      throw new DomainException(DomainErrorCode.WEAK_PASSWORD, 'Password must be a string');
    }

    if (raw.length < MIN_LENGTH) {
      throw new DomainException(
        DomainErrorCode.WEAK_PASSWORD,
        `Password must be at least ${MIN_LENGTH} characters long`,
      );
    }

    if (raw.length > MAX_LENGTH) {
      throw new DomainException(
        DomainErrorCode.WEAK_PASSWORD,
        `Password must not exceed ${MAX_LENGTH} characters`,
      );
    }

    if (!HAS_UPPERCASE.test(raw)) {
      throw new DomainException(
        DomainErrorCode.WEAK_PASSWORD,
        'Password must contain at least one uppercase letter',
      );
    }

    if (!HAS_LOWERCASE.test(raw)) {
      throw new DomainException(
        DomainErrorCode.WEAK_PASSWORD,
        'Password must contain at least one lowercase letter',
      );
    }

    if (!HAS_DIGIT.test(raw)) {
      throw new DomainException(
        DomainErrorCode.WEAK_PASSWORD,
        'Password must contain at least one digit',
      );
    }

    if (!HAS_SPECIAL.test(raw)) {
      throw new DomainException(
        DomainErrorCode.WEAK_PASSWORD,
        'Password must contain at least one special character',
      );
    }

    if (COMMON_PASSWORDS.has(raw.toLowerCase())) {
      throw new DomainException(
        DomainErrorCode.COMMON_PASSWORD,
        'Password is too common — please choose a more unique password',
      );
    }

    return new RawPassword(raw);
  }

  /** Returns the raw plaintext value. Only used by CredentialService for hashing. */
  getValue(): string {
    return this.value;
  }
}
