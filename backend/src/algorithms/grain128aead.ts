/**
 * Grain-128AEAD Stream Cipher / AEAD Implementation
 * Based on the NIST Lightweight Cryptography competition specification
 * Key: 128 bits (16 bytes), IV: 96 bits (12 bytes)
 * State: 128-bit LFSR + 128-bit NFSR + 64-bit accumulator + 64-bit shift register
 */

export interface Grain128State {
  lfsr: number[];   // 128 bits as array of bits
  nfsr: number[];   // 128 bits as array of bits
  acc: number[];    // 64-bit accumulator
  sr: number[];     // 64-bit shift register
}

export interface Grain128StepState {
  step: number;
  keystreamBit: number;
  lfsrSlice: number[];
  nfsrSlice: number[];
}

export interface Grain128Result {
  ciphertext: Uint8Array;
  keystream: Uint8Array;
  tag: string;
  initialState: Grain128State;
  steps: Grain128StepState[];
}

// LFSR feedback polynomial: x^128 + x^7 + x^38 + x^70 + x^81 + x^96 + 1
function lfsrFeedback(s: number[]): number {
  return s[0] ^ s[7] ^ s[38] ^ s[70] ^ s[81] ^ s[96];
}

// NFSR feedback function (nonlinear)
function nfsrFeedback(b: number[], s: number[]): number {
  return (
    s[0] ^
    b[0] ^
    b[26] ^
    b[56] ^
    b[91] ^
    b[96] ^
    (b[3] & b[67]) ^
    (b[11] & b[13]) ^
    (b[17] & b[18]) ^
    (b[27] & b[59]) ^
    (b[40] & b[48]) ^
    (b[61] & b[65]) ^
    (b[68] & b[84]) ^
    (b[88] & b[92] & b[93] & b[95]) ^
    (b[22] & b[24] & b[25]) ^
    (b[70] & b[78] & b[82])
  );
}

// Output function h(x) - takes bits from LFSR and NFSR
function outputFunction(b: number[], s: number[]): number {
  const x0 = b[12];
  const x1 = s[8];
  const x2 = s[13];
  const x3 = s[20];
  const x4 = b[95];
  const x5 = s[42];
  const x6 = s[60];
  const x7 = s[79];
  const x8 = s[94];

  return (
    (x1 & x4) ^
    (x0 & x3) ^
    (x2 & x5) ^
    (x3 & x4) ^
    (x4 & x6) ^
    (x5 & x7) ^
    (x6 & x8) ^
    x0 ^
    x1 ^
    x2 ^
    x3 ^
    x4 ^
    x6 ^
    x7 ^
    x8
  );
}

function bytesToBits(bytes: Uint8Array): number[] {
  const bits: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    for (let b = 0; b < 8; b++) {
      bits.push((bytes[i] >> b) & 1);
    }
  }
  return bits;
}

function bitsToBytes(bits: number[]): Uint8Array {
  const bytes = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    bytes[i >> 3] |= bits[i] << (i & 7);
  }
  return bytes;
}

/**
 * Initialize Grain-128AEAD state
 */
function initGrain128(key: Uint8Array, iv: Uint8Array): {
  lfsr: number[];
  nfsr: number[];
  initialState: Grain128State;
} {
  // Load IV into LFSR[0..95], set LFSR[96..126]=1, LFSR[127]=1
  const lfsr = new Array(128).fill(0);
  const ivBits = bytesToBits(iv);
  for (let i = 0; i < 96; i++) lfsr[i] = ivBits[i];
  for (let i = 96; i < 127; i++) lfsr[i] = 1;
  lfsr[127] = 1;

  // Load key into NFSR
  const nfsr = bytesToBits(key);

  const initialState: Grain128State = {
    lfsr: [...lfsr],
    nfsr: [...nfsr],
    acc: new Array(64).fill(0),
    sr: new Array(64).fill(0),
  };

  // 256 pre-output rounds (output fed back into both registers)
  for (let i = 0; i < 256; i++) {
    const y = outputFunction(nfsr, lfsr);
    const lNew = lfsrFeedback(lfsr) ^ y;
    const nNew = nfsrFeedback(nfsr, lfsr) ^ y;
    lfsr.shift();
    lfsr.push(lNew);
    nfsr.shift();
    nfsr.push(nNew);
  }

  return { lfsr, nfsr, initialState };
}

/**
 * Clock Grain-128AEAD and get one keystream bit
 */
function grainClock(lfsr: number[], nfsr: number[]): number {
  const y = outputFunction(nfsr, lfsr);
  const lNew = lfsrFeedback(lfsr);
  const nNew = nfsrFeedback(nfsr, lfsr);
  lfsr.shift();
  lfsr.push(lNew);
  nfsr.shift();
  nfsr.push(nNew);
  return y;
}

/**
 * Encrypt using Grain-128AEAD with authentication
 */
export function grain128Encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  captureSteps = false,
  maxSteps = 64
): Grain128Result {
  if (key.length !== 16) throw new Error('Grain-128AEAD key must be 16 bytes (128 bits)');
  if (iv.length !== 12) throw new Error('Grain-128AEAD IV must be 12 bytes (96 bits)');

  const { lfsr, nfsr, initialState } = initGrain128(key, iv);

  // Generate accumulator and SR initialization keystream (64+64 bits)
  const accBits: number[] = [];
  const srBits: number[] = [];
  for (let i = 0; i < 64; i++) accBits.push(grainClock(lfsr, nfsr));
  for (let i = 0; i < 64; i++) srBits.push(grainClock(lfsr, nfsr));

  const acc = [...accBits];
  const sr = [...srBits];

  const steps: Grain128StepState[] = [];

  // Process AAD - generate authentication bits interleaved
  const aadBits = bytesToBits(aad);
  for (let i = 0; i < aadBits.length; i++) {
    const y = grainClock(lfsr, nfsr);
    // Update accumulator with AAD bit
    for (let j = 63; j > 0; j--) acc[j] = acc[j - 1];
    acc[0] = (acc[0] ^ aadBits[i]) & 1;
  }

  // Encrypt plaintext
  const cipherBits: number[] = [];
  const keystreamBits: number[] = [];
  const ptBits = bytesToBits(plaintext);

  for (let i = 0; i < ptBits.length; i++) {
    const y = grainClock(lfsr, nfsr);

    if (captureSteps && i < maxSteps) {
      steps.push({
        step: i,
        keystreamBit: y,
        lfsrSlice: lfsr.slice(0, 8),
        nfsrSlice: nfsr.slice(0, 8),
      });
    }

    keystreamBits.push(y);
    cipherBits.push(ptBits[i] ^ y);

    // Update SR and accumulate
    for (let j = 63; j > 0; j--) sr[j] = sr[j - 1];
    sr[0] = ptBits[i];
    // XOR sr into acc for MAC
    for (let j = 0; j < 64; j++) acc[j] ^= sr[j] & y;
  }

  // Simple 64-bit tag from accumulator
  const tagBytes = bitsToBytes(acc);
  const tag = Buffer.from(tagBytes).toString('hex');

  return {
    ciphertext: bitsToBytes(cipherBits),
    keystream: bitsToBytes(keystreamBits),
    tag,
    initialState: { ...initialState, acc: [...acc], sr: [...sr] },
    steps,
  };
}

/**
 * Decrypt using Grain-128AEAD
 *
 * NOTE: grain128Encrypt computes the MAC tag using plaintext bits to update SR.
 * If we just call grain128Encrypt(ciphertext,...) the SR gets updated with
 * ciphertext bits instead of plaintext bits → wrong tag every time.
 * This function properly decrypts AND computes the tag over plaintext bits.
 */
export function grain128Decrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  expectedTag?: string,
  captureSteps = false,
  maxSteps = 64
): Grain128Result & { valid: boolean } {
  if (key.length !== 16) throw new Error('Grain-128AEAD key must be 16 bytes (128 bits)');
  if (iv.length !== 12) throw new Error('Grain-128AEAD IV must be 12 bytes (96 bits)');

  const { lfsr, nfsr, initialState } = initGrain128(key, iv);

  // Generate accumulator and SR initialization keystream (64+64 bits)
  const accBits: number[] = [];
  const srBits: number[] = [];
  for (let i = 0; i < 64; i++) accBits.push(grainClock(lfsr, nfsr));
  for (let i = 0; i < 64; i++) srBits.push(grainClock(lfsr, nfsr));

  const acc = [...accBits];
  const sr = [...srBits];

  const steps: Grain128StepState[] = [];

  // Process AAD — identical to encryption
  const aadBits = bytesToBits(aad);
  for (let i = 0; i < aadBits.length; i++) {
    grainClock(lfsr, nfsr);
    for (let j = 63; j > 0; j--) acc[j] = acc[j - 1];
    acc[0] = (acc[0] ^ aadBits[i]) & 1;
  }

  // Decrypt ciphertext and compute MAC over plaintext bits
  const plaintextBits: number[] = [];
  const keystreamBits: number[] = [];
  const ctBits = bytesToBits(ciphertext);

  for (let i = 0; i < ctBits.length; i++) {
    const y = grainClock(lfsr, nfsr);

    if (captureSteps && i < maxSteps) {
      steps.push({
        step: i,
        keystreamBit: y,
        lfsrSlice: lfsr.slice(0, 8),
        nfsrSlice: nfsr.slice(0, 8),
      });
    }

    keystreamBits.push(y);
    // XOR ciphertext bit with keystream → plaintext bit
    const ptBit = ctBits[i] ^ y;
    plaintextBits.push(ptBit);

    // Update SR with PLAINTEXT bit (same as encryption) → correct MAC
    for (let j = 63; j > 0; j--) sr[j] = sr[j - 1];
    sr[0] = ptBit;
    // XOR sr into acc for MAC
    for (let j = 0; j < 64; j++) acc[j] ^= sr[j] & y;
  }

  const tagBytes = bitsToBytes(acc);
  const tag = Buffer.from(tagBytes).toString('hex');

  const valid = !expectedTag || tag === expectedTag;

  return {
    ciphertext: bitsToBytes(plaintextBits),
    keystream: bitsToBytes(keystreamBits),
    tag,
    initialState: { ...initialState, acc: [...acc], sr: [...sr] },
    steps,
    valid,
  };
}