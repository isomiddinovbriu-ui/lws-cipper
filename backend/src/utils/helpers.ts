import { v4 as uuidv4 } from 'uuid';

/**
 * Parse a hex string into Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '').replace(/^0x/i, '');
  if (clean.length % 2 !== 0) throw new Error('Hex string must have even length');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert Uint8Array to base64
 */
export function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/**
 * Convert base64 to Uint8Array
 */
export function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

/**
 * Pad or trim a byte array to exactly `length` bytes
 * If too short, pads with zeros; if too long, truncates
 */
export function normalizeKeyLength(bytes: Uint8Array, length: number): Uint8Array {
  const result = new Uint8Array(length);
  result.set(bytes.slice(0, Math.min(bytes.length, length)));
  return result;
}

/**
 * Parse key from string input (supports hex, base64, or raw UTF-8)
 */
export function parseKeyInput(input: string, format: 'hex' | 'base64' | 'utf8' = 'hex'): Uint8Array {
  switch (format) {
    case 'hex': return hexToBytes(input);
    case 'base64': return base64ToBytes(input);
    case 'utf8': return new TextEncoder().encode(input);
  }
}

/**
 * Generate a unique request ID
 */
export function generateRequestId(): string {
  return uuidv4();
}

/**
 * Format bytes into human-readable size
 */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(10)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(10)} MB`;
}

/**
 * Calculate throughput in MB/s
 */
export function calculateThroughput(bytes: number, milliseconds: number): number {
  return (bytes / 1024 / 1024) / (milliseconds / 1000);
}

/**
 * Build a TXT report for an encryption result
 */
export function buildTxtReport(data: {
  algorithm: string;
  key: string;
  nonce: string;
  aad?: string;
  ciphertext: string;
  tag?: string;
  timeTaken: number;
  throughput: number;
  originalFilename?: string;
  originalMimeType?: string;
}): string {
  const lines = [
    '--------------------------------',
    `Algorithm: ${data.algorithm}`,
    `Key: ${data.key}`,
    `Nonce: ${data.nonce}`,
  ];
  if (data.originalFilename) lines.push(`Original Filename: ${data.originalFilename}`);
  if (data.originalMimeType) lines.push(`Original Mime Type: ${data.originalMimeType}`);
  if (data.aad) lines.push(`Additional Auth Data: ${data.aad}`);
  lines.push(`Ciphertext: ${data.ciphertext}`);
  if (data.tag) lines.push(`Authentication Tag: ${data.tag}`);
  lines.push(`Time taken: ${data.timeTaken.toFixed(3)} ms`);
  lines.push(`Throughput: ${data.throughput.toFixed(4)} MB/s`);
  lines.push('--------------------------------');
  return lines.join('\n');
}

/**
 * Validate key/nonce lengths for each algorithm
 */
export const ALGORITHM_PARAMS: Record<string, { keyBytes: number; nonceBytes: number; isAEAD: boolean }> = {
  trivium: { keyBytes: 10, nonceBytes: 10, isAEAD: false },
  grain128aead: { keyBytes: 16, nonceBytes: 12, isAEAD: true },
  mickey: { keyBytes: 10, nonceBytes: 10, isAEAD: false },
  chacha20: { keyBytes: 32, nonceBytes: 12, isAEAD: false },
  ascon: { keyBytes: 16, nonceBytes: 16, isAEAD: true },
};

export function validateCryptoParams(
  algorithm: string,
  keyHex: string,
  nonceHex: string
): { valid: boolean; error?: string } {
  const params = ALGORITHM_PARAMS[algorithm.toLowerCase()];
  if (!params) return { valid: false, error: `Unknown algorithm: ${algorithm}` };

  try {
    const keyBytes = hexToBytes(keyHex);
    const nonceBytes = hexToBytes(nonceHex);

    if (keyBytes.length !== params.keyBytes) {
      return {
        valid: false,
        error: `${algorithm} requires ${params.keyBytes * 8}-bit key (${params.keyBytes} bytes). Got ${keyBytes.length} bytes.`,
      };
    }
    if (nonceBytes.length !== params.nonceBytes) {
      return {
        valid: false,
        error: `${algorithm} requires ${params.nonceBytes * 8}-bit nonce (${params.nonceBytes} bytes). Got ${nonceBytes.length} bytes.`,
      };
    }
  } catch (e) {
    return { valid: false, error: `Invalid hex encoding: ${(e as Error).message}` };
  }

  return { valid: true };
}

/**
 * Recursively convert values that JSON can't serialize (BigInt, Uint8Array)
 * into serializable representations (hex strings for BigInt/bytes).
 */
export function serializeForJson(obj: unknown): unknown {
  const seen = new WeakSet();

  function recurse(v: any): any {
    if (v === null || v === undefined) return v;
    const t = typeof v;
    if (t === 'bigint') return '0x' + (v as bigint).toString(16);
    if (t === 'number' || t === 'string' || t === 'boolean') return v;
    if (v instanceof Uint8Array) return bytesToHex(v as Uint8Array);
    if (Array.isArray(v)) return v.map(recurse);
    if (v instanceof Date) return v.toISOString();
    if (t === 'object') {
      if (seen.has(v)) return '[Circular]';
      seen.add(v);
      const out: Record<string, any> = {};
      for (const key of Object.keys(v)) {
        out[key] = recurse(v[key]);
      }
      return out;
    }
    return String(v);
  }

  return recurse(obj);
}
