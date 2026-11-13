import { Base32Error } from './base32';
import { buildOtpauthUri } from './otpauth';
import { qrSvg } from './qr';
import {
  generateSecret,
  secondsRemaining,
  secretFromBase32,
  totp,
  verifyTotp,
  type HashAlg,
  type OtpResult,
} from './totp';

const secretInput = document.querySelector('#secret') as HTMLInputElement;
const issuerInput = document.querySelector('#issuer') as HTMLInputElement;
const accountInput = document.querySelector('#account') as HTMLInputElement;
const algorithmInput = document.querySelector('#algorithm') as HTMLSelectElement;
const digitsInput = document.querySelector('#digits') as HTMLSelectElement;
const periodInput = document.querySelector('#period') as HTMLInputElement;
const statusEl = document.querySelector('#status') as HTMLParagraphElement;
const codeEl = document.querySelector('#code') as HTMLParagraphElement;
const barFill = document.querySelector('#bar-fill') as HTMLSpanElement;
const countdownEl = document.querySelector('#countdown') as HTMLParagraphElement;
const qrEl = document.querySelector('#qr') as HTMLDivElement;
const uriEl = document.querySelector('#uri') as HTMLTextAreaElement;
const verifyInput = document.querySelector('#verify-input') as HTMLInputElement;
const verifyResult = document.querySelector('#verify-result') as HTMLParagraphElement;
const hoodUnix = document.querySelector('#hood-unix') as HTMLElement;
const hoodCounter = document.querySelector('#hood-counter') as HTMLElement;
const hoodHmac = document.querySelector('#hood-hmac') as HTMLElement;
const hoodOffset = document.querySelector('#hood-offset') as HTMLElement;
const hoodBytes = document.querySelector('#hood-bytes') as HTMLElement;

let lastUri = '';
let lastCounter = -1;
let latest: OtpResult | null = null;
let tickTimer = 0;

function setStatus(message: string, kind: 'ok' | 'error' | '' = '') {
  statusEl.textContent = message;
  if (kind) {
    statusEl.dataset.kind = kind;
  } else {
    delete statusEl.dataset.kind;
  }
}

function setVerify(message: string, kind: 'ok' | 'error' | '' = '') {
  verifyResult.textContent = message;
  if (kind) {
    verifyResult.dataset.kind = kind;
  } else {
    delete verifyResult.dataset.kind;
  }
}

function readOptions() {
  const algorithm = algorithmInput.value as HashAlg;
  const digits = Number(digitsInput.value) === 8 ? 8 : 6;
  const rawPeriod = Number(periodInput.value);
  const period = Number.isInteger(rawPeriod) && rawPeriod >= 15 && rawPeriod <= 120 ? rawPeriod : 30;
  return {
    secretText: secretInput.value,
    issuer: issuerInput.value,
    account: accountInput.value,
    algorithm,
    digits,
    period,
  };
}

function formatCode(code: string): string {
  if (code.length === 6) {
    return `${code.slice(0, 3)} ${code.slice(3)}`;
  }
  if (code.length === 8) {
    return `${code.slice(0, 4)} ${code.slice(4)}`;
  }
  return code;
}

async function copyText(value: string, label: string) {
  try {
    await navigator.clipboard.writeText(value);
    setStatus(`Copied ${label}.`, 'ok');
  } catch {
    setStatus(`Could not copy ${label}. Select the text and copy it manually.`, 'error');
  }
}

async function refreshQr(uri: string) {
  if (uri === lastUri) {
    return;
  }
  lastUri = uri;
  uriEl.value = uri;
  try {
    qrEl.innerHTML = await qrSvg(uri);
  } catch {
    qrEl.replaceChildren();
    setStatus('Could not draw the QR code from the otpauth URI.', 'error');
  }
}

function clearLive() {
  latest = null;
  lastCounter = -1;
  codeEl.textContent = '------';
  countdownEl.textContent = '—';
  barFill.style.width = '0%';
  hoodUnix.textContent = '—';
  hoodCounter.textContent = '—';
  hoodHmac.textContent = '—';
  hoodOffset.textContent = '—';
  hoodBytes.textContent = '—';
}

async function tick() {
  const opts = readOptions();
  let secret: Uint8Array;
  try {
    secret = secretFromBase32(opts.secretText);
  } catch (error) {
    clearLive();
    lastUri = '';
    uriEl.value = '';
    qrEl.replaceChildren();
    const message = error instanceof Base32Error ? error.message : 'Invalid secret.';
    setStatus(message, 'error');
    return;
  }

  if (!opts.account.trim()) {
    clearLive();
    lastUri = '';
    uriEl.value = '';
    qrEl.replaceChildren();
    setStatus('Account label is required to build the otpauth URI.', 'error');
    return;
  }

  const now = Date.now() / 1000;
  try {
    const result = await totp(secret, now, opts.digits, opts.period, opts.algorithm);
    latest = result;
    codeEl.textContent = formatCode(result.code);
    const remaining = secondsRemaining(now, opts.period);
    const ratio = remaining / opts.period;
    barFill.style.width = `${Math.max(0, Math.min(1, ratio)) * 100}%`;
    countdownEl.textContent = `${Math.ceil(remaining)}s left in this ${opts.period}s window`;
    hoodUnix.textContent = Math.floor(now).toString();
    if (result.counter !== lastCounter) {
      lastCounter = result.counter;
      hoodCounter.textContent = String(result.counter);
      hoodHmac.textContent = result.hmacHex;
      hoodOffset.textContent = String(result.offset);
      hoodBytes.textContent = result.codeBytesHex;
    }
    const uri = buildOtpauthUri({
      secretBase32: opts.secretText,
      issuer: opts.issuer,
      account: opts.account,
      algorithm: opts.algorithm,
      digits: opts.digits,
      period: opts.period,
    });
    setStatus('');
    await refreshQr(uri);
  } catch (error) {
    clearLive();
    const message = error instanceof Error ? error.message : 'Could not generate a code.';
    setStatus(message, 'error');
  }
}

async function onVerify() {
  const opts = readOptions();
  try {
    const secret = secretFromBase32(opts.secretText);
    const now = Date.now() / 1000;
    const result = await verifyTotp(
      secret,
      verifyInput.value,
      now,
      opts.digits,
      opts.period,
      opts.algorithm,
      1,
    );
    if (result.ok) {
      const skew =
        result.delta === 0
          ? 'Matches the current time step.'
          : result.delta === -1
            ? 'Matches the previous time step (−1).'
            : 'Matches the next time step (+1).';
      setVerify(`Valid. ${skew}`, 'ok');
    } else {
      setVerify('No match in the current ±1 window.', 'error');
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Could not verify the code.';
    setVerify(message, 'error');
  }
}

function startClock() {
  window.clearInterval(tickTimer);
  void tick();
  tickTimer = window.setInterval(() => {
    void tick();
  }, 250);
}

document.querySelector('#generate')?.addEventListener('click', () => {
  secretInput.value = generateSecret();
  setVerify('');
  startClock();
});

document.querySelector('#copy-secret')?.addEventListener('click', () => {
  void copyText(secretInput.value.replace(/\s+/g, ''), 'the secret');
});

document.querySelector('#copy-code')?.addEventListener('click', () => {
  if (!latest) {
    setStatus('No code to copy yet.', 'error');
    return;
  }
  void copyText(latest.code, 'the code');
});

document.querySelector('#copy-uri')?.addEventListener('click', () => {
  if (!uriEl.value) {
    setStatus('No URI to copy yet.', 'error');
    return;
  }
  void copyText(uriEl.value, 'the otpauth URI');
});

document.querySelector('#verify')?.addEventListener('click', () => {
  void onVerify();
});

verifyInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    void onVerify();
  }
});

for (const el of [secretInput, issuerInput, accountInput, algorithmInput, digitsInput, periodInput]) {
  el.addEventListener('input', () => {
    lastUri = '';
    lastCounter = -1;
    startClock();
  });
}

secretInput.value = generateSecret();
startClock();
