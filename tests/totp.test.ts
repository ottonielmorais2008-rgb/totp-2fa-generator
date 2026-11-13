import { describe, expect, it } from 'vitest';
import { encoderBytes } from '../src/bytes';
import {
  generateSecret,
  hotp,
  totp,
  totpCounter,
  verifyTotp,
} from '../src/totp';
import { decodeBase32 } from '../src/base32';

// RFC 4226 Appendix D — HMAC-SHA1, 6 digits, secret = ASCII "12345678901234567890"
const RFC4226_SECRET = encoderBytes('12345678901234567890');
const RFC4226_CODES = [
  '755224',
  '287082',
  '359152',
  '969429',
  '338314',
  '254676',
  '287922',
  '162583',
  '399871',
  '520489',
];

// RFC 6238 Appendix B — 8-digit TOTP, period 30
const RFC6238_TIMES = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000];
const RFC6238_SHA1 = ['94287082', '07081804', '14050471', '89005924', '69279037', '65353130'];
const RFC6238_SHA256 = ['46119246', '68084774', '67062674', '91819424', '90698825', '77737706'];
const RFC6238_SHA512 = ['90693936', '25091201', '99943326', '93441116', '38618901', '47863826'];

const SHA1_SECRET = encoderBytes('12345678901234567890');
const SHA256_SECRET = encoderBytes('12345678901234567890123456789012');
const SHA512_SECRET = encoderBytes(
  '1234567890123456789012345678901234567890123456789012345678901234',
);

describe('RFC 4226 HOTP', () => {
  it('matches the official SHA-1 6-digit test vectors for counters 0–9', async () => {
    for (let counter = 0; counter < RFC4226_CODES.length; counter += 1) {
      const result = await hotp(RFC4226_SECRET, counter, 6, 'SHA-1');
      expect(result.code).toBe(RFC4226_CODES[counter]);
      expect(result.counter).toBe(counter);
      expect(result.hmacHex).toMatch(/^[0-9a-f]{40}$/);
      expect(result.offset).toBeGreaterThanOrEqual(0);
      expect(result.offset).toBeLessThanOrEqual(15);
      expect(result.codeBytesHex).toHaveLength(8);
    }
  });
});

describe('RFC 6238 TOTP', () => {
  it('uses floor(unix / period) as the moving counter', () => {
    expect(totpCounter(59, 30)).toBe(1);
    expect(totpCounter(1111111109, 30)).toBe(37037036);
    expect(totpCounter(0, 30)).toBe(0);
  });

  it('matches the official 8-digit SHA-1 test vectors', async () => {
    for (let i = 0; i < RFC6238_TIMES.length; i += 1) {
      const result = await totp(SHA1_SECRET, RFC6238_TIMES[i], 8, 30, 'SHA-1');
      expect(result.code).toBe(RFC6238_SHA1[i]);
    }
  });

  it('matches the official 8-digit SHA-256 test vectors', async () => {
    for (let i = 0; i < RFC6238_TIMES.length; i += 1) {
      const result = await totp(SHA256_SECRET, RFC6238_TIMES[i], 8, 30, 'SHA-256');
      expect(result.code).toBe(RFC6238_SHA256[i]);
    }
  });

  it('matches the official 8-digit SHA-512 test vectors', async () => {
    for (let i = 0; i < RFC6238_TIMES.length; i += 1) {
      const result = await totp(SHA512_SECRET, RFC6238_TIMES[i], 8, 30, 'SHA-512');
      expect(result.code).toBe(RFC6238_SHA512[i]);
    }
  });
});

describe('TOTP verification window', () => {
  it('accepts the current step and the immediate ±1 neighbours, but not ±2', async () => {
    const unix = 1111111111;
    const period = 30;
    const current = await totp(SHA1_SECRET, unix, 8, period, 'SHA-1');
    const previous = await totp(SHA1_SECRET, unix - period, 8, period, 'SHA-1');
    const next = await totp(SHA1_SECRET, unix + period, 8, period, 'SHA-1');
    const twoBack = await totp(SHA1_SECRET, unix - 2 * period, 8, period, 'SHA-1');
    const twoAhead = await totp(SHA1_SECRET, unix + 2 * period, 8, period, 'SHA-1');

    expect((await verifyTotp(SHA1_SECRET, current.code, unix, 8, period, 'SHA-1')).ok).toBe(true);
    expect((await verifyTotp(SHA1_SECRET, current.code, unix, 8, period, 'SHA-1')).delta).toBe(0);

    expect((await verifyTotp(SHA1_SECRET, previous.code, unix, 8, period, 'SHA-1')).ok).toBe(true);
    expect((await verifyTotp(SHA1_SECRET, previous.code, unix, 8, period, 'SHA-1')).delta).toBe(-1);

    expect((await verifyTotp(SHA1_SECRET, next.code, unix, 8, period, 'SHA-1')).ok).toBe(true);
    expect((await verifyTotp(SHA1_SECRET, next.code, unix, 8, period, 'SHA-1')).delta).toBe(1);

    expect((await verifyTotp(SHA1_SECRET, twoBack.code, unix, 8, period, 'SHA-1')).ok).toBe(false);
    expect((await verifyTotp(SHA1_SECRET, twoAhead.code, unix, 8, period, 'SHA-1')).ok).toBe(false);
    expect((await verifyTotp(SHA1_SECRET, '00000000', unix, 8, period, 'SHA-1')).ok).toBe(false);
    expect((await verifyTotp(SHA1_SECRET, 'abc', unix, 8, period, 'SHA-1')).ok).toBe(false);
  });

  it('accepts codes with spaces in the input', async () => {
    const result = await verifyTotp(SHA1_SECRET, '1405 0471', 1111111111, 8, 30, 'SHA-1');
    expect(result).toEqual({ ok: true, delta: 0 });
  });
});

describe('generateSecret', () => {
  it('returns a 32-character Base32 string for the 160-bit default', () => {
    const secret = generateSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(decodeBase32(secret).byteLength).toBe(20);
  });
});
