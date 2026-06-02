import { triviumEncrypt } from '../algorithms/trivium';
import { grain128Encrypt } from '../algorithms/grain128aead';
import { mickeyEncrypt } from '../algorithms/mickey';
import { chaCha20Encrypt } from '../algorithms/chacha20';
import { asconEncrypt } from '../algorithms/ascon';

type WorkerRequest = {
  type: 'benchmark';
  data: ArrayBuffer;
  frameId: string;
  captureTs: number;
};

type AlgoResult = {
  algorithm: string;
  frameId: string;
  captureTs: number;
  dataSize: number;
  encryptTime: number;
  decryptTime: number;
  throughput: number;
  ciphertextHex: string;
};

function normalizeKey(size: number): Uint8Array {
  const k = new Uint8Array(size);
  // deterministic non-zero pattern for consistent measurements
  for (let i = 0; i < size; i++) k[i] = i & 0xff;
  return k;
}

console.log('[BENCHMARK] Worker initialized');

self.addEventListener('message', async (ev: MessageEvent) => {
  console.log('[BENCHMARK] Worker received message', ev.data);
  const msg = ev.data as WorkerRequest;
  if (msg.type !== 'benchmark') return;

  const raw = new Uint8Array(msg.data);
  const size = raw.length;

  const results: AlgoResult[] = [];

  // Trivium
  try {
    const keyT = normalizeKey(10);
    const nonceT = normalizeKey(10);
    const t0 = performance.now();
    const enc = triviumEncrypt(raw, keyT, nonceT);
    const t1 = performance.now();
    const dtEnc = t1 - t0;
    const t2 = performance.now();
    triviumEncrypt(enc.ciphertext, keyT, nonceT);
    const t3 = performance.now();
    results.push({
      algorithm: 'trivium',
      frameId: msg.frameId,
      captureTs: msg.captureTs,
      dataSize: size,
      encryptTime: dtEnc,
      decryptTime: t3 - t2,
      throughput: (size / (1024 * 1024)) / (dtEnc / 1000),
      ciphertextHex: Array.from(enc.ciphertext).map(b => b.toString(16).padStart(2, '0')).join(''),
    });
  } catch (err) {}

  // Grain
  try {
    const key = normalizeKey(16);
    const nonce = normalizeKey(12);
    const t0 = performance.now();
    const enc = grain128Encrypt(raw, key, nonce);
    const t1 = performance.now();
    const dtEnc = t1 - t0;
    const t2 = performance.now();
    grain128Encrypt(enc.ciphertext, key, nonce);
    const t3 = performance.now();
    results.push({
      algorithm: 'grain128aead',
      frameId: msg.frameId,
      captureTs: msg.captureTs,
      dataSize: size,
      encryptTime: dtEnc,
      decryptTime: t3 - t2,
      throughput: (size / (1024 * 1024)) / (dtEnc / 1000),
      ciphertextHex: Array.from(enc.ciphertext).map(b => b.toString(16).padStart(2, '0')).join(''),
    });
  } catch (err) {}

  // MICKEY
  try {
    const key = normalizeKey(10);
    const nonce = normalizeKey(10);
    const t0 = performance.now();
    const enc = mickeyEncrypt(raw, key, nonce);
    const t1 = performance.now();
    const dtEnc = t1 - t0;
    const t2 = performance.now();
    mickeyEncrypt(enc.ciphertext, key, nonce);
    const t3 = performance.now();
    results.push({
      algorithm: 'mickey',
      frameId: msg.frameId,
      captureTs: msg.captureTs,
      dataSize: size,
      encryptTime: dtEnc,
      decryptTime: t3 - t2,
      throughput: (size / (1024 * 1024)) / (dtEnc / 1000),
      ciphertextHex: Array.from(enc.ciphertext).map(b => b.toString(16).padStart(2, '0')).join(''),
    });
  } catch (err) {}

  // ChaCha20
  try {
    const key = normalizeKey(32);
    const nonce = normalizeKey(12);
    const t0 = performance.now();
    const enc = chaCha20Encrypt(raw, key, nonce);
    const t1 = performance.now();
    const dtEnc = t1 - t0;
    const t2 = performance.now();
    chaCha20Encrypt(enc.ciphertext, key, nonce);
    const t3 = performance.now();
    results.push({
      algorithm: 'chacha20',
      frameId: msg.frameId,
      captureTs: msg.captureTs,
      dataSize: size,
      encryptTime: dtEnc,
      decryptTime: t3 - t2,
      throughput: (size / (1024 * 1024)) / (dtEnc / 1000),
      ciphertextHex: Array.from(enc.ciphertext).map(b => b.toString(16).padStart(2, '0')).join(''),
    });
  } catch (err) {}

  // Ascon
  try {
    const key = normalizeKey(16);
    const nonce = normalizeKey(16);
    const t0 = performance.now();
    const enc = asconEncrypt(raw, key, nonce);
    const t1 = performance.now();
    const dtEnc = t1 - t0;
    const t2 = performance.now();
    asconEncrypt(enc.ciphertext, key, nonce);
    const t3 = performance.now();
    results.push({
      algorithm: 'ascon',
      frameId: msg.frameId,
      captureTs: msg.captureTs,
      dataSize: size,
      encryptTime: dtEnc,
      decryptTime: t3 - t2,
      throughput: (size / (1024 * 1024)) / (dtEnc / 1000),
      ciphertextHex: Array.from(enc.ciphertext).map(b => b.toString(16).padStart(2, '0')).join(''),
    });
  } catch (err) {}

  console.log('[BENCHMARK] Worker computed results', results);
  self.postMessage({ type: 'result', results });
});
