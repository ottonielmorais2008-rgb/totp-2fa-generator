/** Copy into a fresh ArrayBuffer so TypeScript 5.9 accepts the view as BufferSource. */
export function asBufferSource(data: Uint8Array): ArrayBuffer {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

export function toHex(data: Uint8Array): string {
  return Array.from(data, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function encoderBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
