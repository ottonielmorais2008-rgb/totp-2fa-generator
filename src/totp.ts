import { asBufferSource, toHex } from './bytes';
import { decodeBase32, encodeBase32 } from './base32';

export type HashAlg = 'SHA-1' | 'SHA-256' | 'SHA-512';

export const HASH_ALGS: readonly HashAlg[] = ['SHA-1', 'SHA-256', 'SHA-512'];

export interface Truncation {
  offset: number;
  truncated: number;
  codeBytes: Uint8Array;
}

export interface OtpResult {
  code: string;
  counter: number;
  hmacHex: string;
  offset: number;
  truncated: number;
  codeBytesHex: string;
}

export interface VerifyResult {
  ok: boolean;
  delta: number | null;
}

export function otpauthAlgorithm(alg: HashAlg): 'SHA1' | 'SHA256' | 'SHA512' {
  switch (alg) {
    case 'SHA-1':
      return 'SHA1';
    case 'SHA-256':
      return 'SHA256';
    case 'SHA-512':
      return 'SHA512';
  }
}

export function counterToBytes(counter: number): Uint8Array {
  if (!Number.isInteger(counter) || counter < 0) {
    throw new Error('Counter must be a non-negative integer.');
  }
  const buf = new Uint8Array(8);
  let value = BigInt(counter);
  for (let i = 7; i >= 0; i -= 1) {
    buf[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return buf;
}

export async function hmacSha(
  alg: HashAlg,
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    asBufferSource(key),
    { name: 'HMAC', hash: alg },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, asBufferSource(data));
  return new Uint8Array(sig);
}

/** RFC 4226 dynamic truncation. */
export function dynamicTruncate(hmacBytes: Uint8Array): Truncation {
  if (hmacBytes.length < 20) {
    throw new Error('HMAC output is too short to truncate.');
  }
  const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
  const codeBytes = hmacBytes.slice(offset, offset + 4);
  const truncated =
    ((codeBytes[0] & 0x7f) << 24) |
    ((codeBytes[1] & 0xff) << 16) |
    ((codeBytes[2] & 0xff) << 8) |
    (codeBytes[3] & 0xff);
  return { offset, truncated, codeBytes };
}

export async function hotp(
  secret: Uint8Array,
  counter: number,
  digits: number,
  alg: HashAlg,
): Promise<OtpResult> {
  if (digits !== 6 && digits !== 8) {
    throw new Error('Digits must be 6 or 8.');
  }
  const mac = await hmacSha(alg, secret, counterToBytes(counter));
  const { offset, truncated, codeBytes } = dynamicTruncate(mac);
  const modulus = 10 ** digits;
  const code = (truncated % modulus).toString().padStart(digits, '0');
  return {
    code,
    counter,
    hmacHex: toHex(mac),
    offset,
    truncated,
    codeBytesHex: toHex(codeBytes),
  };
}

export function totpCounter(unixSeconds: number, period: number): number {
  if (!Number.isFinite(unixSeconds) || unixSeconds < 0) {
    throw new Error('Unix time must be a non-negative number.');
  }
  if (!Number.isInteger(period) || period <= 0) {
    throw new Error('Period must be a positive integer.');
  }
  return Math.floor(unixSeconds / period);
}

export function secondsRemaining(unixSeconds: number, period: number): number {
  const elapsed = unixSeconds % period;
  return period - elapsed === period ? period : period - elapsed;
}

export async function totp(
  secret: Uint8Array,
  unixSeconds: number,
  digits: number,
  period: number,
  alg: HashAlg,
): Promise<OtpResult> {
  return hotp(secret, totpCounter(unixSeconds, period), digits, alg);
}

export function normalizeCode(input: string, digits: number): string | null {
  const digitsOnly = input.replace(/\s+/g, '');
  if (!new RegExp(`^\\d{${digits}}$`).test(digitsOnly)) {
    return null;
  }
  return digitsOnly;
}

/** Check the current time step and ±window neighbouring steps (default ±1). */
export async function verifyTotp(
  secret: Uint8Array,
  code: string,
  unixSeconds: number,
  digits: number,
  period: number,
  alg: HashAlg,
  window = 1,
): Promise<VerifyResult> {
  const expected = normalizeCode(code, digits);
  if (expected === null) {
    return { ok: false, delta: null };
  }
  const current = totpCounter(unixSeconds, period);
  for (let delta = -window; delta <= window; delta += 1) {
    const step = current + delta;
    if (step < 0) {
      continue;
    }
    const result = await hotp(secret, step, digits, alg);
    if (result.code === expected) {
      return { ok: true, delta };
    }
  }
  return { ok: false, delta: null };
}

/** Cryptographically random Base32 secret. Default 160 bits (20 bytes, 32 characters). */
export function generateSecret(bitLength = 160): string {
  if (!Number.isInteger(bitLength) || bitLength < 80 || bitLength % 8 !== 0) {
    throw new Error('Secret size must be a multiple of 8 bits, at least 80.');
  }
  const bytes = new Uint8Array(bitLength / 8);
  crypto.getRandomValues(bytes);
  return encodeBase32(bytes);
}

export function secretFromBase32(input: string): Uint8Array {
  return decodeBase32(input);
}
