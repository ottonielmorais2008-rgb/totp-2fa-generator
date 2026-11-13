import { otpauthAlgorithm, type HashAlg } from './totp';

export interface OtpauthOptions {
  secretBase32: string;
  issuer: string;
  account: string;
  algorithm: HashAlg;
  digits: number;
  period: number;
}

/**
 * Build an otpauth://totp URI that Google Authenticator, 1Password and Aegis accept.
 * The secret is written unpadded. Issuer and account are percent-encoded.
 */
export function buildOtpauthUri(opts: OtpauthOptions): string {
  const secret = opts.secretBase32.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!secret) {
    throw new Error('Secret is empty.');
  }
  const issuer = opts.issuer.trim();
  const account = opts.account.trim();
  if (!account) {
    throw new Error('Account label is required.');
  }

  const label = issuer
    ? `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`
    : encodeURIComponent(account);

  const params = [
    `secret=${encodeURIComponent(secret)}`,
    `algorithm=${otpauthAlgorithm(opts.algorithm)}`,
    `digits=${opts.digits}`,
    `period=${opts.period}`,
  ];
  if (issuer) {
    params.push(`issuer=${encodeURIComponent(issuer)}`);
  }

  return `otpauth://totp/${label}?${params.join('&')}`;
}
