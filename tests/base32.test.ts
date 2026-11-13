import { describe, expect, it } from 'vitest';
import { Base32Error, decodeBase32, encodeBase32 } from '../src/base32';

const utf8 = (text: string) => new TextEncoder().encode(text);

describe('RFC 4648 Base32', () => {
  const vectors: Array<[string, string]> = [
    ['', ''],
    ['f', 'MY======'],
    ['fo', 'MZXQ===='],
    ['foo', 'MZXW6==='],
    ['foob', 'MZXW6YQ='],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI======'],
  ];

  it('encodes the official test vectors with padding', () => {
    for (const [plain, encoded] of vectors) {
      expect(encodeBase32(utf8(plain), true)).toBe(encoded);
    }
  });

  it('encodes without padding by default', () => {
    expect(encodeBase32(utf8('foobar'))).toBe('MZXW6YTBOI');
    expect(encodeBase32(utf8('f'))).toBe('MY');
  });

  it('decodes padded and unpadded input, including lowercase, spaces and hyphens', () => {
    expect(new TextDecoder().decode(decodeBase32('MZXW6YTBOI======'))).toBe('foobar');
    expect(new TextDecoder().decode(decodeBase32('MZXW6YTBOI'))).toBe('foobar');
    expect(new TextDecoder().decode(decodeBase32('mzxw 6ytb-oi'))).toBe('foobar');
  });

  it('rejects empty and invalid input', () => {
    expect(() => decodeBase32('')).toThrow(Base32Error);
    expect(() => decodeBase32('   ')).toThrow(Base32Error);
    expect(() => decodeBase32('====')).toThrow(Base32Error);
    expect(() => decodeBase32('MZX1')).toThrow(Base32Error);
    expect(() => decodeBase32('MZXW6!')).toThrow(Base32Error);
    expect(() => decodeBase32('01')).toThrow(Base32Error);
  });

  it('round-trips 20 random-looking bytes (a typical 160-bit TOTP secret)', () => {
    const bytes = Uint8Array.from({ length: 20 }, (_, i) => (i * 17 + 3) & 0xff);
    const encoded = encodeBase32(bytes);
    expect(encoded).toHaveLength(32);
    expect(encoded.includes('=')).toBe(false);
    expect(decodeBase32(encoded)).toEqual(bytes);
  });
});
