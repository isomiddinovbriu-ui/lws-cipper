import 'express-async-errors';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import swaggerUi from 'swagger-ui-express';
import path from 'path';
import fs from 'fs';

import { cryptoRouter } from './routes/crypto';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { logger } from './utils/logger';

// Ensure logs directory exists
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const app = express();
const PORT = parseInt(process.env.PORT ?? '3099', 10);

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// CORS - allow frontend dev server
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') ?? ['http://localhost:5173', 'http://localhost:3000'],
  credentials: true,
}));

// Request parsing
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(compression());

// Rate limiting
app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500,
  message: { success: false, error: { message: 'Too many requests, please try again later.' } },
  standardHeaders: true,
  legacyHeaders: false,
}));

// Request logging
app.use((req, _res, next) => {
  logger.info(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Swagger API documentation
const swaggerDocument = {
  openapi: '3.0.0',
  info: {
    title: 'Crypto Platform API',
    version: '1.0.0',
    description: 'Lightweight Cryptographic Algorithms Analysis Platform',
    contact: { email: 'admin@crypto-platform.local' },
  },
  servers: [{ url: `http://localhost:${PORT}`, description: 'Development server' }],
  tags: [
    { name: 'Crypto', description: 'Encryption and decryption operations' },
    { name: 'Benchmark', description: 'Performance benchmarking' },
  ],
  paths: {
    '/api/crypto/algorithms': {
      get: {
        tags: ['Crypto'],
        summary: 'Get supported algorithms',
        responses: { 200: { description: 'Algorithm list' } },
      },
    },
    '/api/crypto/encrypt': {
      post: {
        tags: ['Crypto'],
        summary: 'Encrypt text with one or all algorithms',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['text', 'key', 'nonce'],
                properties: {
                  text: { type: 'string', description: 'Plaintext to encrypt' },
                  algorithms: { type: 'array', items: { type: 'string' }, description: 'Algorithm IDs. Empty = all' },
                  key: { type: 'string', description: 'Key in hex (length depends on algorithm)' },
                  nonce: { type: 'string', description: 'Nonce/IV in hex' },
                  aad: { type: 'string', description: 'Additional auth data in hex (AEAD only)' },
                  captureSteps: { type: 'boolean', description: 'Capture internal state steps' },
                },
              },
            },
          },
        },
        responses: { 200: { description: 'Encryption results' } },
      },
    },
    '/api/crypto/decrypt': {
      post: {
        tags: ['Crypto'],
        summary: 'Decrypt ciphertext',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['algorithm', 'ciphertext', 'key', 'nonce'],
                properties: {
                  algorithm: { type: 'string' },
                  ciphertext: { type: 'string', description: 'Hex-encoded ciphertext' },
                  ciphertextEncoding: { type: 'string', enum: ['hex', 'base64'] },
                  key: { type: 'string' },
                  nonce: { type: 'string' },
                  aad: { type: 'string' },
                  tag: { type: 'string', description: 'Auth tag for AEAD verification' },
                },
              },
            },
          },
        },
        responses: { 200: { description: 'Decryption result' } },
      },
    },
    '/api/crypto/benchmark': {
      post: {
        tags: ['Benchmark'],
        summary: 'Run performance benchmark',
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  algorithms: { type: 'array', items: { type: 'string' } },
                  dataSizes: { type: 'array', items: { type: 'number' } },
                },
              },
            },
          },
        },
        responses: { 200: { description: 'Benchmark results' } },
      },
    },
  },
};

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// API routes
app.use('/api/crypto', cryptoRouter);

// Root endpoint
app.get('/', (_req, res) => {
  res.json({
    name: 'Crypto Platform API',
    version: '1.0.0',
    docs: `/api-docs`,
    health: `/api/crypto/health`,
  });
});

// Error handling (must be last)
app.use(notFoundHandler);
app.use(errorHandler);

app.listen(PORT, () => {
  logger.info(`🔐 Crypto Platform API running on http://localhost:${PORT}`);
  logger.info(`📚 API Docs available at http://localhost:${PORT}/api-docs`);
});

export default app;
