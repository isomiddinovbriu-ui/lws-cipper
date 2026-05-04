import { Router, Request, Response } from 'express';
import { encryptData, decryptData, AlgorithmName } from '../services/cryptoService';
import { runBenchmarkSuite, benchmarkCustomData } from '../services/benchmark';
import { uploadMiddleware, uploadResultFile } from '../middleware/upload';
import { createError } from '../middleware/errorHandler';
import { bytesToBase64, bytesToHex, hexToBytes, ALGORITHM_PARAMS } from '../utils/helpers';
import { logger } from '../utils/logger';

export const cryptoRouter = Router();

const ALL_ALGORITHMS: AlgorithmName[] = ['trivium', 'grain128aead', 'mickey', 'chacha20', 'ascon'];

/**
 * @swagger
 * /api/crypto/algorithms:
 *   get:
 *     summary: Get list of supported algorithms with metadata
 *     tags: [Crypto]
 *     responses:
 *       200:
 *         description: Algorithm list
 */
cryptoRouter.get('/algorithms', (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: [
      {
        id: 'trivium',
        name: 'Trivium',
        type: 'Stream Cipher',
        keyBits: 80,
        nonceBits: 80,
        isAEAD: false,
        family: 'eSTREAM',
        description: 'Ultra-lightweight stream cipher with 288-bit state across three shift registers.',
        strengths: ['Very low hardware footprint', 'Simple design', 'High speed in hardware'],
        iotSuitability: 'Excellent',
      },
      {
        id: 'grain128aead',
        name: 'Grain-128AEAD',
        type: 'AEAD Stream Cipher',
        keyBits: 128,
        nonceBits: 96,
        isAEAD: true,
        family: 'eSTREAM / NIST LWC',
        description: 'Hardware-oriented AEAD stream cipher based on LFSR + NFSR with authentication.',
        strengths: ['Authenticated encryption', '128-bit security', 'NIST finalist'],
        iotSuitability: 'Excellent',
      },
      {
        id: 'mickey',
        name: 'MICKEY-v2',
        type: 'Stream Cipher',
        keyBits: 80,
        nonceBits: 80,
        isAEAD: false,
        family: 'eSTREAM',
        description: 'Mutual Irregular Clocking KE-generator with two irregularly clocked registers.',
        strengths: ['Resistance to algebraic attacks', 'Irregular clocking', 'Low power'],
        iotSuitability: 'Good',
      },
      {
        id: 'chacha20',
        name: 'ChaCha20',
        type: 'Stream Cipher',
        keyBits: 256,
        nonceBits: 96,
        isAEAD: false,
        family: 'RFC 7539',
        description: 'ARX-based stream cipher with 20 rounds, successor to Salsa20.',
        strengths: ['256-bit security', 'Software-optimized', 'Widely deployed (TLS 1.3)'],
        iotSuitability: 'Moderate (software-focused)',
      },
      {
        id: 'ascon',
        name: 'Ascon-AEAD128',
        type: 'AEAD',
        keyBits: 128,
        nonceBits: 128,
        isAEAD: true,
        family: 'NIST LWC Standard',
        description: 'NIST standardized lightweight AEAD based on sponge construction with Ascon permutation.',
        strengths: ['NIST LWC winner', '128-bit AEAD security', 'Compact hardware implementation'],
        iotSuitability: 'Excellent',
      },
    ],
  });
});

/**
 * @swagger
 * /api/crypto/encrypt:
 *   post:
 *     summary: Encrypt text using one or more algorithms
 *     tags: [Crypto]
 */
cryptoRouter.post('/encrypt', async (req: Request, res: Response) => {
  const {
    algorithms,
    text,
    key,
    nonce,
    aad,
    captureSteps,
  } = req.body;

  if (!text || typeof text !== 'string') {
    throw createError('text field is required', 400);
  }
  if (!key || !nonce) {
    throw createError('key and nonce are required', 400);
  }

  const algos: AlgorithmName[] = algorithms?.length ? algorithms : ALL_ALGORITHMS;
  const plaintext = new TextEncoder().encode(text);
  const plaintextBase64 = bytesToBase64(plaintext);

  logger.info(`Encrypting ${plaintext.length} bytes with algorithms: ${algos.join(', ')}`);

  const results = await Promise.all(
    algos.map(algo =>
      encryptData({
        algorithm: algo,
        data: plaintextBase64,
        key,
        nonce,
        aad,
        captureSteps: captureSteps ?? false,
      })
    )
  );

  res.json({ success: true, data: results });
});

/**
 * @swagger
 * /api/crypto/encrypt/file:
 *   post:
 *     summary: Encrypt an uploaded file
 *     tags: [Crypto]
 */
cryptoRouter.post('/encrypt/file', uploadMiddleware.single('file'), async (req: Request, res: Response) => {
  if (!req.file) throw createError('No file uploaded', 400);

  const { algorithm = 'chacha20', key, nonce, aad, captureSteps } = req.body;

  if (!key || !nonce) throw createError('key and nonce are required', 400);

  const fileData = req.file.buffer;
  const fileBase64 = bytesToBase64(fileData);

  logger.info(`Encrypting file: ${req.file.originalname} (${fileData.length} bytes) with ${algorithm}`);

  const result = await encryptData({
    algorithm: algorithm as AlgorithmName,
    data: fileBase64,
    key,
    nonce,
    aad,
    captureSteps: captureSteps === 'true',
  });

  res.json({
    success: true,
    data: {
      ...result,
      originalFilename: req.file.originalname,
      originalMimeType: req.file.mimetype,
      originalSize: fileData.length,
    },
  });
});

/**
 * @swagger
 * /api/crypto/decrypt:
 *   post:
 *     summary: Decrypt ciphertext
 *     tags: [Crypto]
 */
cryptoRouter.post('/decrypt', async (req: Request, res: Response) => {
  const { algorithm, ciphertext, ciphertextEncoding, key, nonce, aad, tag, captureSteps } = req.body;

  if (!algorithm) throw createError('algorithm is required', 400);
  if (!ciphertext) throw createError('ciphertext is required', 400);
  if (!key || !nonce) throw createError('key and nonce are required', 400);

  logger.info(`Decrypting with ${algorithm}`);

  const result = await decryptData({
    algorithm: algorithm as AlgorithmName,
    ciphertext,
    ciphertextEncoding: ciphertextEncoding ?? 'hex',
    key,
    nonce,
    aad,
    tag,
    captureSteps,
  });

  res.json({ success: true, data: result });
});

/**
 * Upload a .txt result file and parse it for decryption
 */
cryptoRouter.post('/decrypt/from-file', uploadResultFile.single('file'), async (req: Request, res: Response) => {
  if (!req.file) throw createError('No file uploaded', 400);

  const content = req.file.buffer.toString('utf-8');

  // Parse the TXT report format
  const parsed: Record<string, string> = {};
  for (const line of content.split('\n')) {
    const match = line.match(/^([^:]+):\s*(.+)$/);
    if (match) {
      parsed[match[1].trim().toLowerCase().replace(/\s+/g, '_')] = match[2].trim();
    }
  }

  const algorithm = parsed['algorithm']?.toLowerCase() as AlgorithmName;
  const key = parsed['key'];
  const nonce = parsed['nonce'];
  const ciphertext = parsed['ciphertext'];
  const tag = parsed['authentication_tag'];

  if (!algorithm || !key || !nonce || !ciphertext) {
    throw createError('Invalid result file format - missing required fields', 400);
  }

  const result = await decryptData({
    algorithm,
    ciphertext,
    ciphertextEncoding: 'hex',
    key,
    nonce,
    tag,
  });

  res.json({ success: true, data: result, parsedFile: parsed });
});

/**
 * @swagger
 * /api/crypto/benchmark:
 *   post:
 *     summary: Run performance benchmark across all algorithms
 *     tags: [Benchmark]
 */
cryptoRouter.post('/benchmark', async (req: Request, res: Response) => {
  const { algorithms, dataSizes } = req.body;

  logger.info('Starting benchmark suite...');
  const suite = await runBenchmarkSuite(
    algorithms ?? undefined,
    dataSizes ?? undefined
  );

  res.json({ success: true, data: suite });
});

/**
 * Benchmark with custom uploaded file
 */
cryptoRouter.post('/benchmark/file', uploadMiddleware.single('file'), async (req: Request, res: Response) => {
  if (!req.file) throw createError('No file uploaded', 400);

  const { algorithms } = req.body;
  const algos: AlgorithmName[] = algorithms?.length ? JSON.parse(algorithms) : ALL_ALGORITHMS;

  const data = req.file.buffer;
  const results = await Promise.all(
    algos.map(algo => benchmarkCustomData(algo, data))
  );

  res.json({ success: true, data: results });
});

/**
 * Generate download response for encrypted file
 */
cryptoRouter.post('/download/encrypted', async (req: Request, res: Response) => {
  const { ciphertextHex, filename = 'encrypted' } = req.body;
  if (!ciphertextHex) throw createError('ciphertextHex is required', 400);

  const bytes = hexToBytes(ciphertextHex);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}.enc"`);
  res.send(Buffer.from(bytes));
});

/**
 * Download TXT report
 */
cryptoRouter.post('/download/report', (req: Request, res: Response) => {
  const { content, filename = 'crypto_report' } = req.body;
  if (!content) throw createError('content is required', 400);

  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}.txt"`);
  res.send(content);
});

/**
 * Export benchmark results as CSV
 */
cryptoRouter.post('/export/csv', (req: Request, res: Response) => {
  const { runs } = req.body;
  if (!runs || !Array.isArray(runs)) throw createError('runs array is required', 400);

  const headers = ['Algorithm', 'DataSize(bytes)', 'EncryptTime(ms)', 'DecryptTime(ms)',
    'ThroughputEnc(MB/s)', 'ThroughputDec(MB/s)', 'MemoryUsed(MB)', 'CPUApprox(%)'];

  const csvLines = [
    headers.join(','),
    ...runs.map((r: Record<string, unknown>) => [
      r.algorithm, r.dataSize, r.encryptTime, r.decryptTime,
      r.throughputEnc, r.throughputDec, r.memoryUsed, r.cpuApprox,
    ].join(',')),
  ];

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="benchmark_results.csv"');
  res.send(csvLines.join('\n'));
});

/**
 * Export results as JSON
 */
cryptoRouter.post('/export/json', (req: Request, res: Response) => {
  const { data, filename = 'crypto_results' } = req.body;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}.json"`);
  res.send(JSON.stringify(data, null, 2));
});

/**
 * Health check
 */
cryptoRouter.get('/health', (_req: Request, res: Response) => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    algorithms: ALL_ALGORITHMS,
  });
});
