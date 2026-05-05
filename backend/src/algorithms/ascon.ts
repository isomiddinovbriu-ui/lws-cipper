/**
 * Ascon-AEAD128 Implementation
 * Based on the NIST Lightweight Cryptography standard (FIPS 202)
 * Key: 128 bits (16 bytes), Nonce: 128 bits (16 bytes)
 * State: 320 bits (5 x 64-bit words)
 * Uses Ascon-128 variant: rate=64 bits, rounds_a=12, rounds_b=6
 */

export interface AsconState {
  x: [bigint, bigint, bigint, bigint, bigint];  // 5 x 64-bit words
}

export interface AsconPermutationStep {
  round: number;
  constant: bigint;
  stateAfterConstantAdd: bigint[];
  stateAfterSBox: bigint[];
  stateAfterLinearLayer: bigint[];
}

export interface AsconStepState {
  phase: 'initialization' | 'aad_processing' | 'encryption' | 'finalization';
  blockIndex: number;
  stateBefore: bigint[];
  stateAfter: bigint[];
  permutationSteps?: AsconPermutationStep[];
}

export interface AsconResult {
  ciphertext: Uint8Array;
  tag: string;
  initialState: AsconState;
  steps: AsconStepState[];
}

// Ascon round constants
const ROUND_CONSTANTS = [
  0xf0n, 0xe1n, 0xd2n, 0xc3n, 0xb4n, 0xa5n,
  0x96n, 0x87n, 0x78n, 0x69n, 0x5an, 0x4bn,
];

const MASK64 = 0xffffffffffffffffn;

function rotr64(x: bigint, n: number): bigint {
  return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;
}

/**
 * Ascon S-box: applied to 5-bit columns across the state words
 * The S-box is a 5-bit -> 5-bit nonlinear function
 */
function sBox(x: [bigint, bigint, bigint, bigint, bigint]): [bigint, bigint, bigint, bigint, bigint] {
  // Ascon S-box defined over 5 bits
  let [x0, x1, x2, x3, x4] = x;
  x0 ^= x4; x4 ^= x3; x2 ^= x1;
  const t = [x0, x1, x2, x3, x4];
  x0 = t[0] ^ (~t[1] & t[2]);
  x1 = t[1] ^ (~t[2] & t[3]);
  x2 = t[2] ^ (~t[3] & t[4]);
  x3 = t[3] ^ (~t[4] & t[0]);
  x4 = t[4] ^ (~t[0] & t[1]);
  x0 = (x0 & MASK64) ^ x1;
  x1 = (x1 & MASK64) ^ x2;
  x2 = (~x2) & MASK64;
  x3 = (x3 & MASK64) ^ x4;

  return [x0 & MASK64, x1 & MASK64, x2 & MASK64, x3 & MASK64, x4 & MASK64];
}

/**
 * Ascon linear diffusion layer
 */
function linearLayer(x: [bigint, bigint, bigint, bigint, bigint]): [bigint, bigint, bigint, bigint, bigint] {
  const [x0, x1, x2, x3, x4] = x;
  return [
    (x0 ^ rotr64(x0, 19) ^ rotr64(x0, 28)) & MASK64,
    (x1 ^ rotr64(x1, 61) ^ rotr64(x1, 39)) & MASK64,
    (x2 ^ rotr64(x2, 1)  ^ rotr64(x2, 6))  & MASK64,
    (x3 ^ rotr64(x3, 10) ^ rotr64(x3, 17)) & MASK64,
    (x4 ^ rotr64(x4, 7)  ^ rotr64(x4, 41)) & MASK64,
  ];
}

/**
 * Single Ascon permutation round
 */
function permRound(
  state: [bigint, bigint, bigint, bigint, bigint],
  roundIdx: number,
  captureStep: boolean
): { state: [bigint, bigint, bigint, bigint, bigint]; step?: AsconPermutationStep } {
  // Add round constant to x2
  const rc = ROUND_CONSTANTS[roundIdx];
  let s: [bigint, bigint, bigint, bigint, bigint] = [...state] as [bigint, bigint, bigint, bigint, bigint];
  s[2] = (s[2] ^ rc) & MASK64;

  const afterRC = captureStep ? [...s].map(v => v) : [];

  // S-box layer
  s = sBox(s);
  const afterSBox = captureStep ? [...s].map(v => v) : [];

  // Linear diffusion layer
  s = linearLayer(s);
  const afterLinear = captureStep ? [...s].map(v => v) : [];

  return {
    state: s,
    step: captureStep ? {
      round: roundIdx,
      constant: rc,
      stateAfterConstantAdd: afterRC,
      stateAfterSBox: afterSBox,
      stateAfterLinearLayer: afterLinear,
    } : undefined,
  };
}

/**
 * Apply Ascon permutation with given number of rounds
 */
function permutation(
  state: [bigint, bigint, bigint, bigint, bigint],
  rounds: number,
  startRound: number,
  captureSteps: boolean
): { state: [bigint, bigint, bigint, bigint, bigint]; steps?: AsconPermutationStep[] } {
  let s = state;
  const steps: AsconPermutationStep[] = [];

  for (let i = 0; i < rounds; i++) {
    const { state: ns, step } = permRound(s, startRound + i, captureSteps);
    s = ns;
    if (step) steps.push(step);
  }

  return { state: s, steps: captureSteps ? steps : undefined };
}

function bytesToBigInt(bytes: Uint8Array, offset: number, length = 8): bigint {
  // Interpret bytes as little-endian into a 64-bit bigint
  let result = 0n;
  for (let i = 0; i < length; i++) {
    result |= (BigInt(bytes[offset + i] ?? 0) << BigInt(8 * i));
  }
  return result & MASK64;
}

function bigIntToBytes(n: bigint, length = 8): Uint8Array {
  // Produce little-endian byte array from bigint
  const result = new Uint8Array(length);
  let v = n & MASK64;
  for (let i = 0; i < length; i++) {
    result[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return result;
}

/**
 * Encrypt using Ascon-128 AEAD
 * Rate = 64 bits = 8 bytes, rounds_a = 12, rounds_b = 6
 */
export function asconEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  captureSteps = false
): AsconResult {
  if (key.length !== 16) throw new Error('Ascon key must be 16 bytes (128 bits)');
  if (nonce.length !== 16) throw new Error('Ascon nonce must be 16 bytes (128 bits)');

  const RATE = 8; // 64 bits
  const ROUNDS_A = 12;
  const ROUNDS_B = 6;

  // IV = algorithm specific 64-bit constant for Ascon-128
  // IV = 0x80400c0600000000 (key_size=128, rate=64, rounds_a=12, rounds_b=6)
  const IV = 0x80400c0600000000n;

  const k0 = bytesToBigInt(key, 0);
  const k1 = bytesToBigInt(key, 8);
  const n0 = bytesToBigInt(nonce, 0);
  const n1 = bytesToBigInt(nonce, 8);

  // Initial state: IV || Key || Nonce
  let state: [bigint, bigint, bigint, bigint, bigint] = [IV, k0, k1, n0, n1];

  const initialState: AsconState = {
    x: [...state] as [bigint, bigint, bigint, bigint, bigint],
  };

  const steps: AsconStepState[] = [];

  // Initialization: apply p^a then XOR key into x3, x4
  const stateBefore = [...state] as bigint[];
  const { state: s1, steps: permSteps } = permutation(state, ROUNDS_A, 0, captureSteps);
  state = s1;
  state[3] ^= k0;
  state[4] ^= k1;

  if (captureSteps) {
    steps.push({
      phase: 'initialization',
      blockIndex: 0,
      stateBefore,
      stateAfter: [...state] as bigint[],
      permutationSteps: permSteps,
    });
  }

  // Process AAD
  if (aad.length > 0) {
    // Pad AAD to rate boundary
    const paddedAAD = new Uint8Array(Math.ceil((aad.length + 1) / RATE) * RATE);
    paddedAAD.set(aad);
    paddedAAD[aad.length] = 0x80; // padding

    for (let i = 0; i < paddedAAD.length; i += RATE) {
      const block = bytesToBigInt(paddedAAD, i);
      const sb = [...state] as bigint[];
      state[0] ^= block;
      const { state: ns } = permutation(state, ROUNDS_B, ROUNDS_A - ROUNDS_B, captureSteps && i === 0);
      state = ns;

      if (captureSteps && i === 0) {
        steps.push({
          phase: 'aad_processing',
          blockIndex: i / RATE,
          stateBefore: sb,
          stateAfter: [...state] as bigint[],
        });
      }
    }
  }

  // Domain separation
  state[4] ^= 1n;

  // Encrypt plaintext
  const ciphertext = new Uint8Array(plaintext.length);

  // Pad plaintext
  const paddedPT = new Uint8Array(Math.ceil((plaintext.length + 1) / RATE) * RATE);
  paddedPT.set(plaintext);
  paddedPT[plaintext.length] = 0x80;

  for (let i = 0; i < paddedPT.length; i += RATE) {
    const block = bytesToBigInt(paddedPT, i);
    const sb = [...state] as bigint[];
    const ctBlock = state[0] ^ block;
    state[0] = ctBlock;

    // Write ciphertext (only actual plaintext bytes, not padding)
    const ctBytes = bigIntToBytes(ctBlock);
    const writeLen = Math.min(RATE, plaintext.length - i);
    for (let j = 0; j < writeLen; j++) {
      ciphertext[i + j] = ctBytes[j];
    }

    if (i + RATE < paddedPT.length) {
      // Not last block
      const { state: ns } = permutation(state, ROUNDS_B, ROUNDS_A - ROUNDS_B, captureSteps && i === 0);
      state = ns;
    }

    if (captureSteps && i < RATE * 2) {
      steps.push({
        phase: 'encryption',
        blockIndex: i / RATE,
        stateBefore: sb,
        stateAfter: [...state] as bigint[],
      });
    }
  }

  // Finalization: XOR key, apply p^a, XOR key
  const sbFinal = [...state] as bigint[];
  state[1] ^= k0;
  state[2] ^= k1;
  const { state: sf } = permutation(state, ROUNDS_A, 0, captureSteps);
  state = sf;
  state[3] ^= k0;
  state[4] ^= k1;

  if (captureSteps) {
    steps.push({
      phase: 'finalization',
      blockIndex: 0,
      stateBefore: sbFinal,
      stateAfter: [...state] as bigint[],
    });
  }

  // Tag = x3 || x4 (last 128 bits)
  const tagBytes = new Uint8Array(16);
  tagBytes.set(bigIntToBytes(state[3]));
  tagBytes.set(bigIntToBytes(state[4]), 8);
  const tag = Buffer.from(tagBytes).toString('hex');

  return { ciphertext, tag, initialState, steps };
}

/**
 * Decrypt using Ascon-128 AEAD
 */
export function asconDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  expectedTag?: string,
  captureSteps = false
): AsconResult & { valid: boolean } {
  if (key.length !== 16) throw new Error('Ascon key must be 16 bytes (128 bits)');
  if (nonce.length !== 16) throw new Error('Ascon nonce must be 16 bytes (128 bits)');

  const RATE = 8;
  const ROUNDS_A = 12;
  const ROUNDS_B = 6;
  const IV = 0x80400c0600000000n;

  const k0 = bytesToBigInt(key, 0);
  const k1 = bytesToBigInt(key, 8);
  const n0 = bytesToBigInt(nonce, 0);
  const n1 = bytesToBigInt(nonce, 8);

  let state: [bigint, bigint, bigint, bigint, bigint] = [IV, k0, k1, n0, n1];
  const initialState: AsconState = { x: [...state] as [bigint, bigint, bigint, bigint, bigint] };
  const steps: AsconStepState[] = [];

  // Initialization
  const { state: s1 } = permutation(state, ROUNDS_A, 0, false);
  state = s1;
  state[3] ^= k0;
  state[4] ^= k1;

  // Process AAD
  if (aad.length > 0) {
    const paddedAAD = new Uint8Array(Math.ceil((aad.length + 1) / RATE) * RATE);
    paddedAAD.set(aad);
    paddedAAD[aad.length] = 0x80;
    for (let i = 0; i < paddedAAD.length; i += RATE) {
      state[0] ^= bytesToBigInt(paddedAAD, i);
      const { state: ns } = permutation(state, ROUNDS_B, ROUNDS_A - ROUNDS_B, false);
      state = ns;
    }
  }

  state[4] ^= 1n;

  // Decrypt ciphertext
  const plaintext = new Uint8Array(ciphertext.length);
  const paddedCT = new Uint8Array(Math.ceil((ciphertext.length + 1) / RATE) * RATE);
  paddedCT.set(ciphertext);
  paddedCT[ciphertext.length] = 0x80;

  for (let i = 0; i < paddedCT.length; i += RATE) {
    const block = bytesToBigInt(paddedCT, i);
    const ptBlock = state[0] ^ block;
    const ptBytes = bigIntToBytes(ptBlock);

    const writeLen = Math.min(RATE, ciphertext.length - i);
    for (let j = 0; j < writeLen; j++) {
      plaintext[i + j] = ptBytes[j];
    }

    // Update state[0] to match what encryption does.
    // Encryption: state[0] = state[0] XOR paddedPlaintext_block (= ctBlock)
    //
    // For non-final blocks: ciphertext block IS ctBlock, so state[0] = block is correct.
    //
    // For the FINAL block: we only have `writeLen` bytes of the real ctBlock stored in
    // `ciphertext`; the rest were never saved. Setting state[0] = paddedCT_fake (which
    // has an artificial 0x80 suffix) diverges from encryption and breaks the tag.
    // Fix: rebuild the padded plaintext (pt_actual || 0x80 || 0x00...) and XOR with
    // the current state, which reconstructs the exact ctBlock encryption produced.
    const isLastBlock = (i + RATE >= paddedCT.length);

    if (isLastBlock) {
      // Reconstruct paddedPT = recovered_plaintext_bytes || 0x80 || 0x00...
      const realPaddedPT = new Uint8Array(RATE);
      for (let j = 0; j < writeLen; j++) realPaddedPT[j] = ptBytes[j];
      if (writeLen < RATE) realPaddedPT[writeLen] = 0x80;
      // state[0] = state[0] XOR paddedPT  (mirrors encryption exactly)
      state[0] = (state[0] ^ bytesToBigInt(realPaddedPT, 0)) & MASK64;
      // No permutation on the last block (same as encryption)
    } else {
      state[0] = block; // block = full ciphertext block = ctBlock ✓
      const { state: ns } = permutation(state, ROUNDS_B, ROUNDS_A - ROUNDS_B, false);
      state = ns;
    }
  }

  // Finalization
  state[1] ^= k0;
  state[2] ^= k1;
  const { state: sf } = permutation(state, ROUNDS_A, 0, false);
  state = sf;
  state[3] ^= k0;
  state[4] ^= k1;

  const tagBytes = new Uint8Array(16);
  tagBytes.set(bigIntToBytes(state[3]));
  tagBytes.set(bigIntToBytes(state[4]), 8);
  const tag = Buffer.from(tagBytes).toString('hex');

  // Normalize expected tag (allow optional 0x prefix and case-insensitive)
  let expectedNormalized: string | undefined = undefined;
  if (expectedTag && typeof expectedTag === 'string') {
    expectedNormalized = expectedTag.replace(/^0x/i, '').trim().toLowerCase();
  }

  const valid = !expectedNormalized || tag === expectedNormalized;

  if (!valid) {
    try {
      // Helpful debug log for investigations (does not expose keys)
      // eslint-disable-next-line no-console
      console.debug('[ascon] tag mismatch', { computed: tag, expected: expectedNormalized });
    } catch {}
  }

  if (captureSteps) {
    steps.push({
      phase: 'finalization',
      blockIndex: 0,
      stateBefore: [...state] as bigint[],
      stateAfter: [...state] as bigint[],
    });
  }

  return { ciphertext: plaintext, tag, initialState, steps, valid };
}