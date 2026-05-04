/**
 * ChaCha20 Stream Cipher Implementation
 * Based on RFC 7539 (IETF ChaCha20)
 * Key: 256 bits (32 bytes), Nonce: 96 bits (12 bytes), Counter: 32 bits
 * 20 rounds of quarter-round operations on a 4x4 matrix of 32-bit words
 */

export interface ChaCha20State {
  state: number[];  // 16x 32-bit words (512 bits total)
}

export interface QuarterRoundStep {
  round: number;
  quarterRound: number;
  a: number;
  b: number;
  c: number;
  d: number;
  indices: [number, number, number, number];
}

export interface ChaCha20StepState {
  blockIndex: number;
  initialState: number[];
  rounds: QuarterRoundStep[];
  finalState: number[];
}

export interface ChaCha20Result {
  ciphertext: Uint8Array;
  keystream: Uint8Array;
  initialState: ChaCha20State;
  steps: ChaCha20StepState[];
  tag?: string;
}

// ChaCha20 constants ("expand 32-byte k")
const CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

function readUInt32LE(buf: Uint8Array, offset: number): number {
  return (
    (buf[offset] |
      (buf[offset + 1] << 8) |
      (buf[offset + 2] << 16) |
      ((buf[offset + 3] & 0xff) * 0x1000000)) >>>
    0
  );
}

function rotl32(v: number, n: number): number {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

/**
 * ChaCha20 quarter round: a,b,c,d mutated in place in the state array
 */
function quarterRound(state: number[], a: number, b: number, c: number, d: number): QuarterRoundStep {
  state[a] = (state[a] + state[b]) >>> 0; state[d] ^= state[a]; state[d] = rotl32(state[d], 16);
  state[c] = (state[c] + state[d]) >>> 0; state[b] ^= state[c]; state[b] = rotl32(state[b], 12);
  state[a] = (state[a] + state[b]) >>> 0; state[d] ^= state[a]; state[d] = rotl32(state[d], 8);
  state[c] = (state[c] + state[d]) >>> 0; state[b] ^= state[c]; state[b] = rotl32(state[b], 7);

  return {
    round: 0,
    quarterRound: 0,
    a: state[a],
    b: state[b],
    c: state[c],
    d: state[d],
    indices: [a, b, c, d],
  };
}

/**
 * Generate one 64-byte ChaCha20 block
 */
function chaCha20Block(
  key: Uint8Array,
  counter: number,
  nonce: Uint8Array,
  captureSteps: boolean
): { keystream: Uint8Array; stepState?: ChaCha20StepState } {
  // Build initial state: constants | key | counter | nonce
  const state = new Array(16);
  state[0] = CONSTANTS[0];
  state[1] = CONSTANTS[1];
  state[2] = CONSTANTS[2];
  state[3] = CONSTANTS[3];
  state[4] = readUInt32LE(key, 0);
  state[5] = readUInt32LE(key, 4);
  state[6] = readUInt32LE(key, 8);
  state[7] = readUInt32LE(key, 12);
  state[8] = readUInt32LE(key, 16);
  state[9] = readUInt32LE(key, 20);
  state[10] = readUInt32LE(key, 24);
  state[11] = readUInt32LE(key, 28);
  state[12] = counter >>> 0;
  state[13] = readUInt32LE(nonce, 0);
  state[14] = readUInt32LE(nonce, 4);
  state[15] = readUInt32LE(nonce, 8);

  const initialState = [...state];
  const working = [...state];
  const roundSteps: QuarterRoundStep[] = [];

  // 20 rounds (10 column rounds + 10 diagonal rounds)
  for (let r = 0; r < 10; r++) {
    // Column rounds
    let qr = quarterRound(working, 0, 4, 8, 12);
    if (captureSteps) roundSteps.push({ ...qr, round: r * 2, quarterRound: 0 });

    qr = quarterRound(working, 1, 5, 9, 13);
    if (captureSteps) roundSteps.push({ ...qr, round: r * 2, quarterRound: 1 });

    qr = quarterRound(working, 2, 6, 10, 14);
    if (captureSteps) roundSteps.push({ ...qr, round: r * 2, quarterRound: 2 });

    qr = quarterRound(working, 3, 7, 11, 15);
    if (captureSteps) roundSteps.push({ ...qr, round: r * 2, quarterRound: 3 });

    // Diagonal rounds
    qr = quarterRound(working, 0, 5, 10, 15);
    if (captureSteps) roundSteps.push({ ...qr, round: r * 2 + 1, quarterRound: 0 });

    qr = quarterRound(working, 1, 6, 11, 12);
    if (captureSteps) roundSteps.push({ ...qr, round: r * 2 + 1, quarterRound: 1 });

    qr = quarterRound(working, 2, 7, 8, 13);
    if (captureSteps) roundSteps.push({ ...qr, round: r * 2 + 1, quarterRound: 2 });

    qr = quarterRound(working, 3, 4, 9, 14);
    if (captureSteps) roundSteps.push({ ...qr, round: r * 2 + 1, quarterRound: 3 });
  }

  // Add initial state to working state (final addition)
  for (let i = 0; i < 16; i++) {
    working[i] = (working[i] + initialState[i]) >>> 0;
  }

  // Serialize to little-endian bytes
  const keystream = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    const v = working[i];
    keystream[i * 4] = v & 0xff;
    keystream[i * 4 + 1] = (v >>> 8) & 0xff;
    keystream[i * 4 + 2] = (v >>> 16) & 0xff;
    keystream[i * 4 + 3] = (v >>> 24) & 0xff;
  }

  const stepState: ChaCha20StepState | undefined = captureSteps
    ? { blockIndex: counter, initialState, rounds: roundSteps, finalState: [...working] }
    : undefined;

  return { keystream, stepState };
}

/**
 * Encrypt using ChaCha20 (RFC 7539)
 */
export function chaCha20Encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  initialCounter = 1,
  captureSteps = false
): ChaCha20Result {
  if (key.length !== 32) throw new Error('ChaCha20 key must be 32 bytes (256 bits)');
  if (nonce.length !== 12) throw new Error('ChaCha20 nonce must be 12 bytes (96 bits)');

  const initialState: ChaCha20State = {
    state: [
      CONSTANTS[0], CONSTANTS[1], CONSTANTS[2], CONSTANTS[3],
      readUInt32LE(key, 0), readUInt32LE(key, 4), readUInt32LE(key, 8), readUInt32LE(key, 12),
      readUInt32LE(key, 16), readUInt32LE(key, 20), readUInt32LE(key, 24), readUInt32LE(key, 28),
      initialCounter >>> 0,
      readUInt32LE(nonce, 0), readUInt32LE(nonce, 4), readUInt32LE(nonce, 8),
    ],
  };

  const ciphertext = new Uint8Array(plaintext.length);
  const keystreamFull = new Uint8Array(plaintext.length);
  const steps: ChaCha20StepState[] = [];

  let pos = 0;
  let counter = initialCounter;

  while (pos < plaintext.length) {
    // Capture steps for first 2 blocks only
    const shouldCapture = captureSteps && steps.length < 2;
    const { keystream, stepState } = chaCha20Block(key, counter, nonce, shouldCapture);

    if (stepState) steps.push(stepState);

    const blockLen = Math.min(64, plaintext.length - pos);
    for (let i = 0; i < blockLen; i++) {
      keystreamFull[pos + i] = keystream[i];
      ciphertext[pos + i] = plaintext[pos + i] ^ keystream[i];
    }

    pos += blockLen;
    counter++;
  }

  return { ciphertext, keystream: keystreamFull, initialState, steps };
}

export const chaCha20Decrypt = chaCha20Encrypt;

/**
 * Poly1305 MAC for ChaCha20-Poly1305
 * Generates the one-time key from ChaCha20 block 0
 */
export function generatePoly1305Key(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  const { keystream } = chaCha20Block(key, 0, nonce, false);
  return keystream.slice(0, 32);
}
