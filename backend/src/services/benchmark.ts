import { triviumEncrypt } from '../algorithms/trivium';
import { grain128Encrypt } from '../algorithms/grain128aead';
import { mickeyEncrypt } from '../algorithms/mickey';
import { chaCha20Encrypt } from '../algorithms/chacha20';
import { asconEncrypt } from '../algorithms/ascon';
import { hexToBytes, calculateThroughput } from '../utils/helpers';

export interface BenchmarkRun {
  algorithm: string;
  dataSize: number;
  encryptTime: number;
  decryptTime: number;
  throughputEnc: number;
  throughputDec: number;
  memoryUsed: number;
  cpuApprox: number;
}

export interface BenchmarkSuite {
  runs: BenchmarkRun[];
  dataSizes: number[];
  timestamp: string;
  fastest: string;
  slowest: string;
}

// Fixed test keys/nonces for reproducible benchmarks
const TEST_VECTORS: Record<string, { key: string; nonce: string }> = {
  trivium:      { key: '0000000000000000000000', nonce: '0000000000000000000000' },
  grain128aead: { key: '000000000000000000000000000000000', nonce: '000000000000000000000000' },
  mickey:       { key: '0000000000000000000000', nonce: '0000000000000000000000' },
  chacha20:     { key: '0000000000000000000000000000000000000000000000000000000000000000', nonce: '000000000000000000000000' },
  ascon:        { key: '00000000000000000000000000000000', nonce: '00000000000000000000000000000000' },
};

function getMemoryMB(): number {
  const mem = process.memoryUsage();
  return Math.round((mem.heapUsed / 1024 / 1024) * 100) / 100;
}

function generateTestData(size: number): Uint8Array {
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) data[i] = i & 0xff;
  return data;
}

async function benchmarkAlgorithm(
  algorithm: string,
  data: Uint8Array
): Promise<BenchmarkRun> {
  const vec = TEST_VECTORS[algorithm] ?? TEST_VECTORS['chacha20'];

  // Normalize key/nonce hex to correct lengths
  const keyMap: Record<string, number> = {
    trivium: 20, grain128aead: 32, mickey: 20, chacha20: 64, ascon: 32,
  };
  const nonceMap: Record<string, number> = {
    trivium: 20, grain128aead: 24, mickey: 20, chacha20: 24, ascon: 32,
  };

  const keyHex = vec.key.slice(0, keyMap[algorithm]).padEnd(keyMap[algorithm], '0');
  const nonceHex = vec.nonce.slice(0, nonceMap[algorithm]).padEnd(nonceMap[algorithm], '0');
  const key = hexToBytes(keyHex);
  const nonce = hexToBytes(nonceHex);

  const memBefore = getMemoryMB();

  // Encryption benchmark
  const encStart = performance.now();
  let encrypted: Uint8Array;
  switch (algorithm) {
    case 'trivium':      encrypted = triviumEncrypt(data, key, nonce).ciphertext; break;
    case 'grain128aead': encrypted = grain128Encrypt(data, key, nonce).ciphertext; break;
    case 'mickey':       encrypted = mickeyEncrypt(data, key, nonce).ciphertext; break;
    case 'chacha20':     encrypted = chaCha20Encrypt(data, key, nonce).ciphertext; break;
    case 'ascon':        encrypted = asconEncrypt(data, key, nonce).ciphertext; break;
    default:             encrypted = data;
  }
  const encEnd = performance.now();
  const encTime = encEnd - encStart;

  // Decryption benchmark
  const decStart = performance.now();
  switch (algorithm) {
    case 'trivium':      triviumEncrypt(encrypted, key, nonce); break;
    case 'grain128aead': grain128Encrypt(encrypted, key, nonce); break;
    case 'mickey':       mickeyEncrypt(encrypted, key, nonce); break;
    case 'chacha20':     chaCha20Encrypt(encrypted, key, nonce); break;
    case 'ascon':        asconEncrypt(encrypted, key, nonce); break;
  }
  const decEnd = performance.now();
  const decTime = decEnd - decStart;

  const memAfter = getMemoryMB();

  return {
    algorithm,
    dataSize: data.length,
    encryptTime: encTime,
    decryptTime: decTime,
    throughputEnc: calculateThroughput(data.length, encTime),
    throughputDec: calculateThroughput(data.length, decTime),
    memoryUsed: Math.max(0, memAfter - memBefore),
    cpuApprox: Math.min(100, (encTime / 1000) * 10),
  };
}

/**
 * Run full benchmark suite across all algorithms and data sizes
 */
export async function runBenchmarkSuite(
  algorithms: string[] = ['trivium', 'grain128aead', 'mickey', 'chacha20', 'ascon'],
  dataSizes: number[] = [1024, 16384, 65536, 262144]
): Promise<BenchmarkSuite> {
  const runs: BenchmarkRun[] = [];

  for (const size of dataSizes) {
    const data = generateTestData(size);
    for (const algo of algorithms) {
      const run = await benchmarkAlgorithm(algo, data);
      runs.push(run);
    }
  }

  // Find fastest and slowest by throughput (largest dataset)
  const largestSize = dataSizes[dataSizes.length - 1];
  const largestRuns = runs.filter(r => r.dataSize === largestSize);
  const fastest = largestRuns.reduce((best, r) =>
    r.throughputEnc > best.throughputEnc ? r : best
  ).algorithm;
  const slowest = largestRuns.reduce((worst, r) =>
    r.throughputEnc < worst.throughputEnc ? r : worst
  ).algorithm;

  return {
    runs,
    dataSizes,
    timestamp: new Date().toISOString(),
    fastest,
    slowest,
  };
}

/**
 * Run benchmark for a specific custom payload
 */
export async function benchmarkCustomData(
  algorithm: string,
  data: Uint8Array
): Promise<BenchmarkRun> {
  return benchmarkAlgorithm(algorithm, data);
}
