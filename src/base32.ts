const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export class Base32Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Base32Error';
  }
}

/** RFC 4648 Base32, default unpadded (the usual form for TOTP secrets). */
export function encodeBase32(data: Uint8Array, padded = false): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 31];
  }

  if (padded) {
    while (output.length % 8 !== 0) {
      output += '=';
    }
  }

  return output;
}

/**
 * Decode RFC 4648 Base32. Accepts lowercase, spaces, hyphens, and optional padding.
 * Throws Base32Error on empty or invalid input.
 */
export function decodeBase32(input: string): Uint8Array {
  const cleaned = input.toUpperCase().replace(/[\s-]/g, '');
  if (cleaned.length === 0) {
    throw new Base32Error('Secret is empty.');
  }
  if (!/^[A-Z2-7]+=*$/.test(cleaned)) {
    throw new Base32Error('Secret is not valid Base32 (use A–Z and 2–7).');
  }

  const body = cleaned.replace(/=+$/, '');
  if (body.length === 0) {
    throw new Base32Error('Secret is empty.');
  }

  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (const ch of body) {
    const idx = ALPHABET.indexOf(ch);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return new Uint8Array(bytes);
}
