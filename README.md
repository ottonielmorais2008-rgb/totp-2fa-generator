# TOTP 2FA Generator

[![CI](https://github.com/ottonielmorais2008-rgb/totp-2fa-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/ottonielmorais2008-rgb/totp-2fa-generator/actions/workflows/ci.yml)

Generate and verify time-based one-time passwords (TOTP) entirely in the browser. A real authenticator app can scan the local QR code and should show the same live code. Nothing is uploaded.

**Live demo:** [https://ottonielmorais2008-rgb.github.io/totp-2fa-generator/](https://ottonielmorais2008-rgb.github.io/totp-2fa-generator/)

## What it does

1. Generates a cryptographically random 160-bit Base32 secret, or lets you paste an existing one.
2. Builds an `otpauth://totp/...` URI from the issuer, account label, algorithm (SHA-1, SHA-256 or SHA-512), digits (6 or 8) and period.
3. Draws a scannable QR code locally as SVG (no third-party QR URL).
4. Shows the current TOTP code with a countdown synchronized to UTC, plus a compact "Under the hood" view of the moving counter (`floor(unix / period)`), HMAC, offset and dynamic truncation bytes.
5. Verifies a typed code against the current time step and the immediate neighbours (±1 period).

## RFC 6238 in short

TOTP is HOTP ([RFC 4226](https://www.rfc-editor.org/rfc/rfc4226)) with a time-based counter: `C = floor(UnixTime / X)`, where `X` is the period (usually 30 seconds). The secret is used as an HMAC key (SHA-1 by default; SHA-256 and SHA-512 are also defined in [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)). Dynamic truncation of the HMAC produces a 6- or 8-digit code. This project implements that math with the Web Crypto API (`crypto.subtle`) and checks itself against the official RFC test vectors.

## Privacy and security

- The page is a static site with **no backend**. Secrets, URIs and codes stay in the current tab.
- A strict Content Security Policy includes `connect-src 'none'`, so the page cannot make network requests.
- This is an educational, local tool. Do not paste a production account secret into a shared or untrusted computer.
- SHA-1 remains the default because it is what most authenticator apps still expect. SHA-256 and SHA-512 work here, but not every app will honour them.

## Run locally

Use this only on your own machine. The public demo is the GitHub Pages link above, not a localhost URL.

```bash
npm ci
npm test
npm run dev
```

Then open the local Vite URL shown in the terminal. `npm run typecheck` and `npm run build` are also available.

## Tests and CI

GitHub Actions runs typecheck, Vitest, and the Vite production build on every pull request and push, and deploys `dist/` to GitHub Pages from `main`.

The tests cover RFC 4648 Base32 (official padded vectors, unpadded TOTP-style secrets, and invalid input), the RFC 4226 HOTP SHA-1 counters 0–9, the RFC 6238 8-digit TOTP vectors for SHA-1, SHA-256 and SHA-512, ±1 window verification, and `otpauth://` URI formatting.

## What went wrong

- A first draft of the URI builder used `URLSearchParams`, which encodes spaces as `+`. Some authenticator apps are strict about `otpauth` query strings, so the URI is built with `encodeURIComponent` instead (`%20` for spaces).
- TypeScript 5.9 types `Uint8Array` more strictly against `BufferSource`. HMAC key and message views are copied into a fresh `ArrayBuffer` before they are passed to `crypto.subtle`.

## License

MIT.
