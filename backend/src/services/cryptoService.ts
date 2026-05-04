import { triviumEncrypt, triviumDecrypt } from '../algorithms/trivium';
import { grain128Encrypt, grain128Decrypt } from '../algorithms/grain128aead';
import { mickeyEncrypt, mickeyDecrypt } from '../algorithms/mickey';
import { chaCha20Encrypt, chaCha20Decrypt } from '../algorithms/chacha20';
import { asconEncrypt, asconDecrypt } from '../algorithms/ascon';
import {
  hexToBytes,
  bytesToHex,
  bytesToBase64,
  base64ToBytes,
  buildTxtReport,
  calculateThroughput,
  normalizeKeyLength,
} from '../utils/helpers';

export type AlgorithmName = 'trivium' | 'grain128aead' | 'mickey' | 'chacha20' | 'ascon';

export interface CryptoRequest {
  algorithm: AlgorithmName;
  data: string;         // base64 encoded input
  key: string;          // hex
  nonce: string;        // hex
  aad?: string;         // hex, for AEAD algorithms
  captureSteps?: boolean;
  originalFilename?: string;
  originalMimeType?: string;
}

export interface CryptoResponse {
  algorithm: string;
  ciphertext: string;   // hex
  ciphertextBase64: string;
  keystream?: string;   // hex (stream ciphers)
  tag?: string;         // AEAD tag hex
  initialState: unknown;
  steps: unknown[];
  timeTaken: number;
  throughput: number;
  txtReport: string;
}

export interface DecryptRequest {
  algorithm: AlgorithmName;
  ciphertext: string;   // hex or base64
  ciphertextEncoding?: 'hex' | 'base64';
  key: string;          // hex
  nonce: string;        // hex
  aad?: string;         // hex
  tag?: string;         // hex, for AEAD verification
  captureSteps?: boolean;
}

export interface DecryptResponse {
  algorithm: string;
  plaintext: string;    // UTF-8 if text, else base64
  plaintextBase64: string;
  valid?: boolean;      // for AEAD tag verification
  timeTaken: number;
}

/**
 * Normalize key length by padding or truncating to expected size
 */
function normalizeKey(keyHex: string, expectedBytes: number): Uint8Array {
  const raw = hexToBytes(keyHex.padEnd(expectedBytes * 2, '0').slice(0, expectedBytes * 2));
  return normalizeKeyLength(raw, expectedBytes);
}

function normalizeNonce(nonceHex: string, expectedBytes: number): Uint8Array {
  const raw = hexToBytes(nonceHex.padEnd(expectedBytes * 2, '0').slice(0, expectedBytes * 2));
  return normalizeKeyLength(raw, expectedBytes);
}

/**
 * Encrypt data using the specified algorithm
 */
export async function encryptData(req: CryptoRequest): Promise<CryptoResponse> {
  const plaintext = base64ToBytes(req.data);
  const captureSteps = req.captureSteps ?? false;
  const aad = req.aad ? hexToBytes(req.aad) : new Uint8Array(0);

  const start = performance.now();
  let result: {
    ciphertext: Uint8Array;
    keystream?: Uint8Array;
    tag?: string;
    initialState: unknown;
    steps: unknown[];
  };

  switch (req.algorithm) {
    case 'trivium': {
      const key = normalizeKey(req.key, 10);
      const nonce = normalizeNonce(req.nonce, 10);
      result = triviumEncrypt(plaintext, key, nonce, captureSteps);
      break;
    }
    case 'grain128aead': {
      const key = normalizeKey(req.key, 16);
      const nonce = normalizeNonce(req.nonce, 12);
      result = grain128Encrypt(plaintext, key, nonce, aad, captureSteps);
      break;
    }
    case 'mickey': {
      const key = normalizeKey(req.key, 10);
      const nonce = normalizeNonce(req.nonce, 10);
      result = mickeyEncrypt(plaintext, key, nonce, captureSteps);
      break;
    }
    case 'chacha20': {
      const key = normalizeKey(req.key, 32);
      const nonce = normalizeNonce(req.nonce, 12);
      result = chaCha20Encrypt(plaintext, key, nonce, 1, captureSteps);
      break;
    }
    case 'ascon': {
      const key = normalizeKey(req.key, 16);
      const nonce = normalizeNonce(req.nonce, 16);
      result = asconEncrypt(plaintext, key, nonce, aad, captureSteps);
      break;
    }
    default:
      throw new Error(`Unknown algorithm: ${req.algorithm}`);
  }

  const timeTaken = performance.now() - start;
  const throughput = calculateThroughput(plaintext.length, timeTaken);
  const ctHex = bytesToHex(result.ciphertext);

  const txtReport = buildTxtReport({
    algorithm: req.algorithm,
    key: req.key,
    nonce: req.nonce,
    aad: req.aad,
    ciphertext: ctHex,
    tag: result.tag,
    timeTaken,
    throughput,
    originalFilename: req.originalFilename,
    originalMimeType: req.originalMimeType,
  });

  return {
    algorithm: req.algorithm,
    ciphertext: ctHex,
    ciphertextBase64: bytesToBase64(result.ciphertext),
    keystream: result.keystream ? bytesToHex(result.keystream) : undefined,
    tag: result.tag,
    initialState: result.initialState,
    steps: result.steps,
    timeTaken,
    throughput,
    txtReport,
  };
}

/**
 * Decrypt data using the specified algorithm
 */
export async function decryptData(req: DecryptRequest): Promise<DecryptResponse> {
  const encoding = req.ciphertextEncoding ?? 'hex';
  const ciphertext = encoding === 'hex'
    ? hexToBytes(req.ciphertext)
    : base64ToBytes(req.ciphertext);

  const aad = req.aad ? hexToBytes(req.aad) : new Uint8Array(0);
  const captureSteps = req.captureSteps ?? false;

  const start = performance.now();
  let plaintext: Uint8Array;
  let valid: boolean | undefined;

  switch (req.algorithm) {
    case 'trivium': {
      const key = normalizeKey(req.key, 10);
      const nonce = normalizeNonce(req.nonce, 10);
      plaintext = triviumDecrypt(ciphertext, key, nonce, captureSteps).ciphertext;
      break;
    }
    case 'grain128aead': {
      const key = normalizeKey(req.key, 16);
      const nonce = normalizeNonce(req.nonce, 12);
      const res = grain128Decrypt(ciphertext, key, nonce, aad, req.tag, captureSteps);
      plaintext = res.ciphertext;
      valid = res.valid;
      break;
    }
    case 'mickey': {
      const key = normalizeKey(req.key, 10);
      const nonce = normalizeNonce(req.nonce, 10);
      plaintext = mickeyDecrypt(ciphertext, key, nonce, captureSteps).ciphertext;
      break;
    }
    case 'chacha20': {
      const key = normalizeKey(req.key, 32);
      const nonce = normalizeNonce(req.nonce, 12);
      plaintext = chaCha20Decrypt(ciphertext, key, nonce, 1, captureSteps).ciphertext;
      break;
    }
    case 'ascon': {
      const key = normalizeKey(req.key, 16);
      const nonce = normalizeNonce(req.nonce, 16);
      const res = asconDecrypt(ciphertext, key, nonce, aad, req.tag, captureSteps);
      plaintext = res.ciphertext;
      valid = res.valid;
      break;
    }
    default:
      throw new Error(`Unknown algorithm: ${req.algorithm}`);
  }

  const timeTaken = performance.now() - start;

  // Try to decode as UTF-8, fall back to base64
  let plaintextStr: string;
  try {
    plaintextStr = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
  } catch {
    plaintextStr = bytesToBase64(plaintext);
  }

  return {
    algorithm: req.algorithm,
    plaintext: plaintextStr,
    plaintextBase64: bytesToBase64(plaintext),
    valid,
    timeTaken,
  };
}
