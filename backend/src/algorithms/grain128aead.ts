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

// LFSR feedback polynomial: x^128 + x^96 + x^81 + x^70 + x^38 + x^7 + 1
function lfsrFeedback(s: number[]): number {
  return s[0] ^ s[7] ^ s[38] ^ s[70] ^ s[81] ^ s[96];
}

// NFSR feedback function (nonlinear), s[0] is LFSR output bit fed in
function nfsrFeedback(b: number[], s: number[]): number {
  return (
    s[0] ^
    b[0] ^
    b[26] ^
    b[56] ^
    b[91] ^
    b[96] ^
    (b[3]  & b[67]) ^
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

/**
 * Output function y_t = h(x) ⊕ s[93] ⊕ b[2] ⊕ b[15] ⊕ b[36] ⊕ b[45] ⊕ b[64] ⊕ b[73] ⊕ b[89]
 *
 * h(x) = x0·x1 ⊕ x2·x3 ⊕ x4·x5 ⊕ x6·x7 ⊕ x0·x4·x8
 *   x0 = s[8],  x1 = b[12], x2 = s[13], x3 = s[20],
 *   x4 = b[95], x5 = s[42], x6 = s[60], x7 = s[79], x8 = s[94]
 *
 * FIX #1: Previous version had wrong quadratic terms, missing triple product,
 *         incorrect linear terms, and swapped x0/x1 in the triple product.
 */
function outputFunction(b: number[], s: number[]): number {
  const x0 = s[8];   // LFSR
  const x1 = b[12];  // NFSR
  const x2 = s[13];  // LFSR
  const x3 = s[20];  // LFSR
  const x4 = b[95];  // NFSR
  const x5 = s[42];  // LFSR
  const x6 = s[60];  // LFSR
  const x7 = s[79];  // LFSR
  const x8 = s[94];  // LFSR

  const hx =
    (x0 & x1) ^
    (x2 & x3) ^
    (x4 & x5) ^
    (x6 & x7) ^
    (x0 & x4 & x8);  // triple product uses s[8], NOT b[12]

  // Linear masking bits from both registers
  return hx ^ s[93] ^ b[2] ^ b[15] ^ b[36] ^ b[45] ^ b[64] ^ b[73] ^ b[89];
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

  // 256 pre-output rounds: output bit fed back into BOTH registers
  for (let i = 0; i < 256; i++) {
    const y    = outputFunction(nfsr, lfsr);
    const lNew = lfsrFeedback(lfsr) ^ y;
    const nNew = nfsrFeedback(nfsr, lfsr) ^ y;
    lfsr.shift(); lfsr.push(lNew);
    nfsr.shift(); nfsr.push(nNew);
  }

  return { lfsr, nfsr, initialState };
}

/**
 * Clock Grain-128AEAD and produce one keystream bit (no feedback during streaming).
 */
function grainClock(lfsr: number[], nfsr: number[]): number {
  const y    = outputFunction(nfsr, lfsr);
  const lNew = lfsrFeedback(lfsr);
  const nNew = nfsrFeedback(nfsr, lfsr);
  lfsr.shift(); lfsr.push(lNew);
  nfsr.shift(); nfsr.push(nNew);
  return y;
}

/**
 * Update the 64-bit accumulator (A) given a keystream bit y and current shift register (S).
 * Rule: if y == 1 then A = A XOR S.
 *
 * This single helper makes the MAC logic identical in encrypt and decrypt.
 */
function updateAcc(acc: number[], sr: number[], y: number): void {
  if (y === 1) {
    for (let j = 0; j < 64; j++) acc[j] ^= sr[j];
  }
}

/**
 * Push a data bit into the front of the 64-bit shift register (S).
 * Bit 0 holds the most recently inserted bit; bit 63 is oldest.
 */
function shiftSR(sr: number[], bit: number): void {
  for (let j = 63; j > 0; j--) sr[j] = sr[j - 1];
  sr[0] = bit;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encrypt using Grain-128AEAD with authentication.
 */
export function grain128Encrypt(
  plaintext:    Uint8Array,
  key:          Uint8Array,
  iv:           Uint8Array,
  aad:          Uint8Array = new Uint8Array(0),
  captureSteps  = false,
  maxSteps      = 64
): Grain128Result {
  if (key.length !== 16) throw new Error('Grain-128AEAD key must be 16 bytes (128 bits)');
  if (iv.length  !== 12) throw new Error('Grain-128AEAD IV must be 12 bytes (96 bits)');

  const { lfsr, nfsr, initialState } = initGrain128(key, iv);

  // FIX #2: SR is initialised FIRST (64 bits), then ACC (next 64 bits).
  // Previous code had the order reversed.
  const sr: number[] = [];
  for (let i = 0; i < 64; i++) sr.push(grainClock(lfsr, nfsr));

  const acc: number[] = [];
  for (let i = 0; i < 64; i++) acc.push(grainClock(lfsr, nfsr));

  const steps: Grain128StepState[] = [];

  // FIX #3: AAD phase — shift SR with each AAD bit, conditionally XOR SR into ACC.
  // Previous code was shifting ACC (!) and XOR-ing the AAD bit into acc[0] — wrong.
  const aadBits = bytesToBits(aad);
  for (let i = 0; i < aadBits.length; i++) {
    const y = grainClock(lfsr, nfsr);
    shiftSR(sr, aadBits[i]);   // insert AAD bit into SR
    updateAcc(acc, sr, y);      // if y==1: ACC ^= SR
  }

  // Encryption phase
  const cipherBits:    number[] = [];
  const keystreamBits: number[] = [];
  const ptBits = bytesToBits(plaintext);

  for (let i = 0; i < ptBits.length; i++) {
    const y = grainClock(lfsr, nfsr);

    if (captureSteps && i < maxSteps) {
      steps.push({
        step:        i,
        keystreamBit: y,
        lfsrSlice:   lfsr.slice(0, 8),
        nfsrSlice:   nfsr.slice(0, 8),
      });
    }

    keystreamBits.push(y);
    cipherBits.push(ptBits[i] ^ y);

    shiftSR(sr, ptBits[i]);    // insert PLAINTEXT bit into SR
    updateAcc(acc, sr, y);     // if y==1: ACC ^= SR
  }

  const tagBytes = bitsToBytes(acc);
  const tag      = Buffer.from(tagBytes).toString('hex');

  return {
    ciphertext:   bitsToBytes(cipherBits),
    keystream:    bitsToBytes(keystreamBits),
    tag,
    initialState: { ...initialState, acc: [...acc], sr: [...sr] },
    steps,
  };
}

/**
 * Decrypt using Grain-128AEAD and verify the authentication tag.
 *
 * The MAC is computed over PLAINTEXT bits (same as during encryption),
 * so the SR must be updated with the recovered plaintext, not the ciphertext.
 */
export function grain128Decrypt(
  ciphertext:   Uint8Array,
  key:          Uint8Array,
  iv:           Uint8Array,
  aad:          Uint8Array = new Uint8Array(0),
  expectedTag?: string,
  captureSteps  = false,
  maxSteps      = 64
): Grain128Result & { valid: boolean } {
  if (key.length !== 16) throw new Error('Grain-128AEAD key must be 16 bytes (128 bits)');
  if (iv.length  !== 12) throw new Error('Grain-128AEAD IV must be 12 bytes (96 bits)');

  const { lfsr, nfsr, initialState } = initGrain128(key, iv);

  // FIX #2 (same as encrypt): SR first, then ACC.
  const sr: number[] = [];
  for (let i = 0; i < 64; i++) sr.push(grainClock(lfsr, nfsr));

  const acc: number[] = [];
  for (let i = 0; i < 64; i++) acc.push(grainClock(lfsr, nfsr));

  const steps: Grain128StepState[] = [];

  // FIX #3 (same as encrypt): correct AAD accumulation.
  const aadBits = bytesToBits(aad);
  for (let i = 0; i < aadBits.length; i++) {
    const y = grainClock(lfsr, nfsr);
    shiftSR(sr, aadBits[i]);
    updateAcc(acc, sr, y);
  }

  // Decryption phase: recover plaintext bits, compute MAC over them.
  const plaintextBits: number[] = [];
  const keystreamBits: number[] = [];
  const ctBits = bytesToBits(ciphertext);

  for (let i = 0; i < ctBits.length; i++) {
    const y = grainClock(lfsr, nfsr);

    if (captureSteps && i < maxSteps) {
      steps.push({
        step:        i,
        keystreamBit: y,
        lfsrSlice:   lfsr.slice(0, 8),
        nfsrSlice:   nfsr.slice(0, 8),
      });
    }

    keystreamBits.push(y);
    const ptBit = ctBits[i] ^ y;   // decrypt
    plaintextBits.push(ptBit);

    shiftSR(sr, ptBit);            // insert PLAINTEXT bit (not ciphertext!)
    updateAcc(acc, sr, y);         // if y==1: ACC ^= SR
  }

  const tagBytes = bitsToBytes(acc);
  const tag      = Buffer.from(tagBytes).toString('hex');
  const valid    = !expectedTag || tag === expectedTag;

  return {
    ciphertext:   bitsToBytes(plaintextBits),   // "ciphertext" field returns plaintext on decrypt
    keystream:    bitsToBytes(keystreamBits),
    tag,
    initialState: { ...initialState, acc: [...acc], sr: [...sr] },
    steps,
    valid,
  };
}