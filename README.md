# CryptoPlatform — Lightweight Cipher Analysis Suite

A full-stack production-ready web application for analyzing, comparing, and visualizing lightweight cryptographic algorithms.

## Supported Algorithms

| Algorithm | Type | Key | Nonce | Family |
|---|---|---|---|---|
| **Trivium** | Stream Cipher | 80-bit (10B) | 80-bit (10B) | eSTREAM |
| **Grain-128AEAD** | AEAD | 128-bit (16B) | 96-bit (12B) | NIST LWC |
| **MICKEY-v2** | Stream Cipher | 80-bit (10B) | 80-bit (10B) | eSTREAM |
| **ChaCha20** | Stream Cipher | 256-bit (32B) | 96-bit (12B) | RFC 7539 |
| **Ascon-AEAD128** | AEAD | 128-bit (16B) | 128-bit (16B) | NIST LWC Standard |

---

## Quick Start

### 1. Start the Backend (Terminal 1)

```bash
cd backend
npm run dev
```

API runs at: **http://localhost:3001**  
Swagger docs: **http://localhost:3001/api-docs**

### 2. Start the Frontend (Terminal 2)

```bash
cd frontend
npm run dev
```

App runs at: **http://localhost:5173**

---

## Features

### Encryption
- Encrypt text or upload files (images, PDFs, videos, text — up to 10 MB)
- Run one or all 5 algorithms simultaneously
- Step-by-step internal state visualization:
  - **Trivium**: 3 shift registers (A/B/C) + tap values
  - **Grain-128AEAD**: LFSR/NFSR bit states
  - **MICKEY-v2**: R/S registers + control bits
  - **ChaCha20**: 4×4 state matrix + quarter round values
  - **Ascon**: 5×64-bit word states per permutation phase
- Download result as `.enc` binary or `.txt` report

### Decryption
- Paste hex/base64 ciphertext manually
- Upload a `.txt` report file — key/nonce/algorithm auto-parsed
- AEAD tag verification for Grain-128AEAD and Ascon

### Benchmarks
- Throughput, latency, memory, CPU across 4 data sizes (1 KB → 256 KB)
- Bar charts, line trend charts, radar comparison chart
- Export as CSV or JSON

### Algorithm Reference
- Key/nonce sizes, internal structure diagrams, security properties
- IoT suitability ratings

---

## Project Structure

```
lwt-cipper/
├── backend/
│   ├── src/
│   │   ├── algorithms/
│   │   │   ├── trivium.ts          # eSTREAM Trivium (288-bit state)
│   │   │   ├── grain128aead.ts     # NIST Grain-128AEAD
│   │   │   ├── mickey.ts           # MICKEY-v2 (irregular clocking)
│   │   │   ├── chacha20.ts         # RFC 7539 ChaCha20
│   │   │   └── ascon.ts            # NIST Ascon-AEAD128 (sponge)
│   │   ├── routes/
│   │   │   └── crypto.ts           # REST API routes
│   │   ├── services/
│   │   │   ├── cryptoService.ts    # Encrypt/decrypt orchestration
│   │   │   └── benchmark.ts        # Performance benchmark runner
│   │   ├── middleware/
│   │   │   ├── errorHandler.ts     # Global error handling
│   │   │   └── upload.ts           # Multer file upload config
│   │   ├── utils/
│   │   │   ├── helpers.ts          # Hex/bytes utilities, validation
│   │   │   └── logger.ts           # Winston logger
│   │   └── index.ts                # Express app + Swagger
│   ├── package.json
│   └── tsconfig.json
│
└── frontend/
    ├── src/
    │   ├── pages/
    │   │   ├── HomePage.tsx         # Landing / feature overview
    │   │   ├── EncryptPage.tsx      # Encrypt text/files
    │   │   ├── DecryptPage.tsx      # Decrypt + AEAD verify
    │   │   ├── BenchmarkPage.tsx    # Charts + performance tables
    │   │   └── AlgorithmsPage.tsx   # Algorithm reference docs
    │   ├── components/
    │   │   ├── Layout.tsx           # Nav + dark mode toggle
    │   │   ├── AlgorithmSelector.tsx
    │   │   ├── CryptoInputs.tsx     # Key/nonce with validation
    │   │   ├── EncryptionResult.tsx # Result card with downloads
    │   │   └── StepVisualization.tsx # Internal state viewer
    │   ├── services/api.ts          # Axios API client
    │   └── hooks/useDarkMode.ts
    ├── package.json
    └── vite.config.ts
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/crypto/algorithms` | List all algorithms with metadata |
| POST | `/api/crypto/encrypt` | Encrypt text (multi-algo) |
| POST | `/api/crypto/encrypt/file` | Encrypt uploaded file |
| POST | `/api/crypto/decrypt` | Decrypt ciphertext |
| POST | `/api/crypto/decrypt/from-file` | Decrypt from .txt report |
| POST | `/api/crypto/benchmark` | Run performance benchmark suite |
| POST | `/api/crypto/download/encrypted` | Download .enc file |
| POST | `/api/crypto/download/report` | Download TXT report |
| POST | `/api/crypto/export/csv` | Export benchmark as CSV |
| POST | `/api/crypto/export/json` | Export results as JSON |
| GET | `/api/crypto/health` | Health check |
| GET | `/api-docs` | Swagger UI |

---

## Key/Nonce Hex Format Reference

```
Trivium:        key=20 hex chars (10B),  nonce=20 hex chars (10B)
Grain-128AEAD:  key=32 hex chars (16B),  nonce=24 hex chars (12B)
MICKEY-v2:      key=20 hex chars (10B),  nonce=20 hex chars (10B)
ChaCha20:       key=64 hex chars (32B),  nonce=24 hex chars (12B)
Ascon-AEAD128:  key=32 hex chars (16B),  nonce=32 hex chars (16B)
```

Example for ChaCha20:
```
Key:   000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Nonce: 000000000000000000000000
```

The frontend's **"Auto-generate"** button fills in correct random values per algorithm.

---

## Environment Variables (Backend)

Create `backend/.env` (optional):

```env
PORT=3001
NODE_ENV=development
ALLOWED_ORIGINS=http://localhost:5173
MAX_FILE_SIZE_MB=10
LOG_LEVEL=info
```
