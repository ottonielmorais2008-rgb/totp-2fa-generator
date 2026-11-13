import { describe, expect, it } from 'vitest';
import { buildOtpauthUri } from '../src/otpauth';

describe('otpauth:// URI', () => {
  it('formats a standard TOTP URI with unpadded secret and encoded label', () => {
    const uri = buildOtpauthUri({
      secretBase32: 'JBSWY3DPEHPK3PXP',
      issuer: 'Example',
      account: 'alice@google.com',
      algorithm: 'SHA-1',
      digits: 6,
      period: 30,
    });

    expect(uri).toBe(
      'otpauth://totp/Example:alice%40google.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30&issuer=Example',
    );
  });

  it('percent-encodes spaces and strips Base32 padding from the secret', () => {
    const uri = buildOtpauthUri({
      secretBase32: 'mzxw 6ytb-oi======',
      issuer: 'Acme Corp',
      account: 'Ada Lovelace',
      algorithm: 'SHA-256',
      digits: 8,
      period: 60,
    });

    expect(uri.startsWith('otpauth://totp/Acme%20Corp:Ada%20Lovelace?')).toBe(true);
    expect(uri).toContain('secret=MZXW6YTBOI&');
    expect(uri).not.toContain('secret=MZXW6YTBOI=');
    expect(uri).toContain('algorithm=SHA256');
    expect(uri).toContain('digits=8');
    expect(uri).toContain('period=60');
    expect(uri).toContain('issuer=Acme%20Corp');
  });

  it('omits the issuer prefix when the issuer is blank', () => {
    const uri = buildOtpauthUri({
      secretBase32: 'JBSWY3DPEHPK3PXP',
      issuer: '  ',
      account: 'solo',
      algorithm: 'SHA-512',
      digits: 6,
      period: 30,
    });
    expect(uri).toBe(
      'otpauth://totp/solo?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=6&period=30',
    );
  });

  it('rejects an empty account label', () => {
    expect(() =>
      buildOtpauthUri({
        secretBase32: 'JBSWY3DPEHPK3PXP',
        issuer: 'Example',
        account: ' ',
        algorithm: 'SHA-1',
        digits: 6,
        period: 30,
      }),
    ).toThrow(/Account label/);
  });
});
