export interface AsconState {
  x: [bigint, bigint, bigint, bigint, bigint];
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

export interface AsconDecryptResult extends AsconResult {
  valid: boolean;
}

const ROUND_CONSTANTS: bigint[] = [
  0xf0n, 0xe1n, 0xd2n, 0xc3n, 0xb4n, 0xa5n,
  0x96n, 0x87n, 0x78n, 0x69n, 0x5an, 0x4bn,
];

const MASK64 = 0xffffffffffffffffn;

const IV_128 = 0x80400c0600000000n;
const RATE     = 8;
const ROUNDS_A = 12;
const ROUNDS_B = 6;

function rotr64(x: bigint, n: number): bigint {
  return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;
}

function bytesToBigInt(bytes: Uint8Array, offset: number, length = 8): bigint {
  let result = 0n;
  for (let i = 0; i < length; i++) {
    result = (result << 8n) | BigInt(bytes[offset + i] ?? 0);
  }
  return result & MASK64;
}

function bigIntToBytes(n: bigint, length = 8): Uint8Array {
  const result = new Uint8Array(length);
  let v = n & MASK64;
  for (let i = length - 1; i >= 0; i--) {
    result[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return result;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, '').trim();
  if (clean.length % 2 !== 0) throw new Error('Noto\'g\'ri hex uzunligi');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function sBox(
  x: [bigint, bigint, bigint, bigint, bigint],
): [bigint, bigint, bigint, bigint, bigint] {
  let [x0, x1, x2, x3, x4] = x;
  x0 ^= x4; x4 ^= x3; x2 ^= x1;
  const t0 = x0, t1 = x1, t2 = x2, t3 = x3, t4 = x4;
  x0 = (t0 ^ (~t1 & t2)) & MASK64;
  x1 = (t1 ^ (~t2 & t3)) & MASK64;
  x2 = (t2 ^ (~t3 & t4)) & MASK64;
  x3 = (t3 ^ (~t4 & t0)) & MASK64;
  x4 = (t4 ^ (~t0 & t1)) & MASK64;
  x1 = (x1 ^ x0) & MASK64;
  x0 = (x0 ^ x4) & MASK64;
  x3 = (x3 ^ x2) & MASK64;
  x2 = (~x2)     & MASK64;
  return [x0, x1, x2, x3, x4];
}

function linearLayer(
  x: [bigint, bigint, bigint, bigint, bigint],
): [bigint, bigint, bigint, bigint, bigint] {
  const [x0, x1, x2, x3, x4] = x;
  return [
    (x0 ^ rotr64(x0, 19) ^ rotr64(x0, 28)) & MASK64,
    (x1 ^ rotr64(x1, 61) ^ rotr64(x1, 39)) & MASK64,
    (x2 ^ rotr64(x2,  1) ^ rotr64(x2,  6)) & MASK64,
    (x3 ^ rotr64(x3, 10) ^ rotr64(x3, 17)) & MASK64,
    (x4 ^ rotr64(x4,  7) ^ rotr64(x4, 41)) & MASK64,
  ];
}

function permRound(
  state: [bigint, bigint, bigint, bigint, bigint],
  roundIdx: number,
  capture: boolean,
): { state: [bigint, bigint, bigint, bigint, bigint]; step?: AsconPermutationStep } {
  const rc = ROUND_CONSTANTS[roundIdx];
  let s: [bigint, bigint, bigint, bigint, bigint] = [...state] as [bigint, bigint, bigint, bigint, bigint];
  s[2] = (s[2] ^ rc) & MASK64;
  const afterRC = capture ? [...s] : [];
  s = sBox(s);
  const afterSBox = capture ? [...s] : [];
  s = linearLayer(s);
  const afterLinear = capture ? [...s] : [];
  return {
    state: s,
    step: capture ? {
      round: roundIdx,
      constant: rc,
      stateAfterConstantAdd: afterRC,
      stateAfterSBox: afterSBox,
      stateAfterLinearLayer: afterLinear,
    } : undefined,
  };
}

function permutation(
  state: [bigint, bigint, bigint, bigint, bigint],
  rounds: number,
  startRound: number,
  capture: boolean,
): { state: [bigint, bigint, bigint, bigint, bigint]; steps: AsconPermutationStep[] } {
  let s = state;
  const steps: AsconPermutationStep[] = [];
  for (let i = 0; i < rounds; i++) {
    const { state: ns, step } = permRound(s, startRound + i, capture);
    s = ns;
    if (step) steps.push(step);
  }
  return { state: s, steps };
}

function pad(data: Uint8Array): Uint8Array {
  const padded = new Uint8Array(Math.ceil((data.length + 1) / RATE) * RATE);
  padded.set(data);
  padded[data.length] = 0x80;
  return padded;
}

export function asconEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  captureSteps = false,
): AsconResult {
  if (key.length !== 16)   throw new Error('Kalit 16 bayt (128 bit) bo\'lishi kerak');
  if (nonce.length !== 16) throw new Error('Nonce 16 bayt (128 bit) bo\'lishi kerak');

  const k0 = bytesToBigInt(key,   0);
  const k1 = bytesToBigInt(key,   8);
  const n0 = bytesToBigInt(nonce, 0);
  const n1 = bytesToBigInt(nonce, 8);

  let state: [bigint, bigint, bigint, bigint, bigint] = [IV_128, k0, k1, n0, n1];

  const initialState: AsconState = { x: [...state] as [bigint, bigint, bigint, bigint, bigint] };
  const steps: AsconStepState[] = [];

  {
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
  }

  if (aad.length > 0) {
    const paddedAAD = pad(aad);
    for (let i = 0; i < paddedAAD.length; i += RATE) {
      const block = bytesToBigInt(paddedAAD, i);
      const stateBefore = captureSteps ? [...state] as bigint[] : [];
      state[0] ^= block;
      const { state: ns, steps: permSteps } = permutation(state, ROUNDS_B, ROUNDS_A - ROUNDS_B, captureSteps);
      state = ns;
      if (captureSteps) {
        steps.push({
          phase: 'aad_processing',
          blockIndex: i / RATE,
          stateBefore,
          stateAfter: [...state] as bigint[],
          permutationSteps: permSteps,
        });
      }
    }
  }

  state[4] ^= 1n;

  const ciphertext = new Uint8Array(plaintext.length);
  const paddedPT   = pad(plaintext);

  for (let i = 0; i < paddedPT.length; i += RATE) {
    const block   = bytesToBigInt(paddedPT, i);
    const stateBefore = captureSteps ? [...state] as bigint[] : [];
    const ctWord  = (state[0] ^ block) & MASK64;
    state[0]      = ctWord;
    const ctBytes  = bigIntToBytes(ctWord);
    const writeLen = Math.min(RATE, plaintext.length - i);
    for (let j = 0; j < writeLen; j++) ciphertext[i + j] = ctBytes[j];
    const isLastBlock = (i + RATE >= paddedPT.length);
    let permSteps: AsconPermutationStep[] = [];
    if (!isLastBlock) {
      const res = permutation(state, ROUNDS_B, ROUNDS_A - ROUNDS_B, captureSteps);
      state     = res.state;
      permSteps = res.steps;
    }
    if (captureSteps) {
      steps.push({
        phase: 'encryption',
        blockIndex: i / RATE,
        stateBefore,
        stateAfter: [...state] as bigint[],
        permutationSteps: permSteps,
      });
    }
  }

  {
    const stateBefore = captureSteps ? [...state] as bigint[] : [];
    state[1] ^= k0;
    state[2] ^= k1;
    const { state: sf, steps: permSteps } = permutation(state, ROUNDS_A, 0, captureSteps);
    state = sf;
    state[3] ^= k0;
    state[4] ^= k1;
    if (captureSteps) {
      steps.push({
        phase: 'finalization',
        blockIndex: 0,
        stateBefore,
        stateAfter: [...state] as bigint[],
        permutationSteps: permSteps,
      });
    }
  }

  const tagBytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    tagBytes.set(bigIntToBytes(state[0], 8).slice(i, i + 1), i);
  }
  const tag = toHex(tagBytes);

  return { ciphertext, tag, initialState, steps };
}
