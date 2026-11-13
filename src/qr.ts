import QRCode from 'qrcode';

/** Render a local SVG QR code. Never uses an external image or network request. */
export async function qrSvg(text: string): Promise<string> {
  return QRCode.toString(text, {
    type: 'svg',
    errorCorrectionLevel: 'M',
    margin: 1,
    width: 240,
    color: {
      dark: '#0b0f16',
      light: '#e8eef8',
    },
  });
}
