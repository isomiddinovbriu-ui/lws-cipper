import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL ?? '/api/crypto';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 120000,
  headers: { 'Content-Type': 'application/json' },
});

// Response interceptor for consistent error handling
api.interceptors.response.use(
  res => res.data,
  error => {
    const message =
      error.response?.data?.error?.message ??
      error.message ??
      'An unexpected error occurred';
    return Promise.reject(new Error(message));
  }
);

// ── Types ────────────────────────────────────────────────────────────────────

export interface Algorithm {
  id: string;
  name: string;
  type: string;
  keyBits: number;
  nonceBits: number;
  isAEAD: boolean;
  family: string;
  description: string;
  strengths: string[];
  iotSuitability: string;
}

export interface EncryptResult {
  algorithm: string;
  ciphertext: string;
  ciphertextBase64: string;
  keystream?: string;
  tag?: string;
  initialState: unknown;
  steps: unknown[];
  timeTaken: number;
  throughput: number;
  txtReport: string;
}

export interface DecryptResult {
  algorithm: string;
  plaintext: string;
  plaintextBase64: string;
  valid?: boolean;
  timeTaken: number;
}

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

// ── API calls ────────────────────────────────────────────────────────────────

export const getAlgorithms = (): Promise<{ success: boolean; data: Algorithm[] }> =>
  api.get('/algorithms') as Promise<{ success: boolean; data: Algorithm[] }>;

export interface EncryptTextPayload {
  text: string;
  algorithms?: string[];
  key: string;
  nonce: string;
  aad?: string;
  captureSteps?: boolean;
}

export const encryptText = (payload: EncryptTextPayload): Promise<{ success: boolean; data: EncryptResult[] }> =>
  api.post('/encrypt', payload) as Promise<{ success: boolean; data: EncryptResult[] }>;

export const encryptFile = (formData: FormData): Promise<{ success: boolean; data: EncryptResult & { originalFilename: string; originalSize: number } }> =>
  api.post('/encrypt/file', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }) as Promise<{ success: boolean; data: EncryptResult & { originalFilename: string; originalSize: number } }>;

export interface DecryptPayload {
  algorithm: string;
  ciphertext: string;
  ciphertextEncoding?: 'hex' | 'base64';
  key: string;
  nonce: string;
  aad?: string;
  tag?: string;
  captureSteps?: boolean;
  originalFilename?: string;
  originalMimeType?: string;
}

export const decryptText = (payload: DecryptPayload): Promise<{ success: boolean; data: DecryptResult; parsedFile?: Record<string, string> }> =>
  api.post('/decrypt', payload) as Promise<{ success: boolean; data: DecryptResult; parsedFile?: Record<string, string> }>;

export const decryptFromFile = (formData: FormData): Promise<{ success: boolean; data: DecryptResult; parsedFile: Record<string, string> }> =>
  api.post('/decrypt/from-file', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }) as Promise<{ success: boolean; data: DecryptResult; parsedFile: Record<string, string> }>;

export const runBenchmark = (payload?: { algorithms?: string[]; dataSizes?: number[] }): Promise<{ success: boolean; data: BenchmarkSuite }> =>
  api.post('/benchmark', payload ?? {}) as Promise<{ success: boolean; data: BenchmarkSuite }>;

export const benchmarkFile = (formData: FormData): Promise<{ success: boolean; data: BenchmarkRun[] }> =>
  api.post('/benchmark/file', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }) as Promise<{ success: boolean; data: BenchmarkRun[] }>;

export const downloadEncryptedFile = async (ciphertextHex: string, filename: string): Promise<void> => {
  const response = await axios.post(
    `${API_BASE}/download/encrypted`,
    { ciphertextHex, filename },
    { responseType: 'blob' }
  );
  const url = URL.createObjectURL(new Blob([response.data]));
  const a = document.createElement('a');
  a.href = url;
  a.download = `${filename}.enc`;
  a.click();
  URL.revokeObjectURL(url);
};

export const downloadReport = async (content: string, filename: string): Promise<void> => {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${filename}.txt`;
  a.click();
  URL.revokeObjectURL(url);
};

export const exportJson = (data: unknown, filename: string): void => {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${filename}.json`;
  a.click();
  URL.revokeObjectURL(url);
};

export const exportCsv = (runs: BenchmarkRun[], filename = 'benchmark_results'): void => {
  const headers = ['Algorithm', 'DataSize(bytes)', 'EncryptTime(ms)', 'DecryptTime(ms)',
    'ThroughputEnc(MB/s)', 'ThroughputDec(MB/s)', 'MemoryUsed(MB)', 'CPUApprox(%)'];
  const rows = runs.map(r => [
    r.algorithm, r.dataSize, r.encryptTime.toFixed(3), r.decryptTime.toFixed(3),
    r.throughputEnc.toFixed(4), r.throughputDec.toFixed(4), r.memoryUsed.toFixed(2), r.cpuApprox.toFixed(2),
  ].join(','));
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${filename}.csv`;
  a.click();
  URL.revokeObjectURL(url);
};
