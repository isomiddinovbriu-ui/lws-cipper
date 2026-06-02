export interface Grain128State {
  lfsr: number[];
  nfsr: number[];
  acc: number[];
  sr: number[];
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

function lfsrFeedback(s: number[]): number {
  return s[0] ^ s[7] ^ s[38] ^ s[70] ^ s[81] ^ s[96];
}

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

function outputFunction(b: number[], s: number[]): number {
  const x0 = s[8];
  const x1 = b[12];
  const x2 = s[13];
  const x3 = s[20];
  const x4 = b[95];
  const x5 = s[42];
  const x6 = s[60];
  const x7 = s[79];
  const x8 = s[94];

  const hx =
    (x0 & x1) ^
    (x2 & x3) ^
    (x4 & x5) ^
    (x6 & x7) ^
    (x0 & x4 & x8);

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

function initGrain128(key: Uint8Array, iv: Uint8Array) {
  const lfsr = new Array(128).fill(0);
  const ivBits = bytesToBits(iv);
  for (let i = 0; i < 96; i++) lfsr[i] = ivBits[i];
  for (let i = 96; i < 127; i++) lfsr[i] = 1;
  lfsr[127] = 1;

  const nfsr = bytesToBits(key);

  const initialState: Grain128State = {
    lfsr: [...lfsr],
    nfsr: [...nfsr],
    acc: new Array(64).fill(0),
    sr: new Array(64).fill(0),
  };

  for (let i = 0; i < 256; i++) {
    const y = outputFunction(nfsr, lfsr);
    const lNew = lfsrFeedback(lfsr) ^ y;
    const nNew = nfsrFeedback(nfsr, lfsr) ^ y;
    lfsr.shift(); lfsr.push(lNew);
    nfsr.shift(); nfsr.push(nNew);
  }

  return { lfsr, nfsr, initialState };
}

function grainClock(lfsr: number[], nfsr: number[]): number {
  const y    = outputFunction(nfsr, lfsr);
  const lNew = lfsrFeedback(lfsr);
  const nNew = nfsrFeedback(nfsr, lfsr);
  lfsr.shift(); lfsr.push(lNew);
  nfsr.shift(); nfsr.push(nNew);
  return y;
}

function updateAcc(acc: number[], sr: number[], y: number): void {
  if (y === 1) {
    for (let j = 0; j < 64; j++) acc[j] ^= sr[j];
  }
}

function shiftSR(sr: number[], bit: number): void {
  for (let j = 63; j > 0; j--) sr[j] = sr[j - 1];
  sr[0] = bit;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

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

  const sr: number[] = [];
  for (let i = 0; i < 64; i++) sr.push(grainClock(lfsr, nfsr));

  const acc: number[] = [];
  for (let i = 0; i < 64; i++) acc.push(grainClock(lfsr, nfsr));

  const steps: Grain128StepState[] = [];

  const aadBits = bytesToBits(aad);
  for (let i = 0; i < aadBits.length; i++) {
    const y = grainClock(lfsr, nfsr);
    shiftSR(sr, aadBits[i]);
    updateAcc(acc, sr, y);
  }

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

    shiftSR(sr, ptBits[i]);
    updateAcc(acc, sr, y);
  }

  const tagBytes = bitsToBytes(acc);
  const tag      = toHex(tagBytes);

  return {
    ciphertext:   bitsToBytes(cipherBits),
    keystream:    bitsToBytes(keystreamBits),
    tag,
    initialState: { ...initialState, acc: [...acc], sr: [...sr] },
    steps,
  };
}

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

  const sr: number[] = [];
  for (let i = 0; i < 64; i++) sr.push(grainClock(lfsr, nfsr));

  const acc: number[] = [];
  for (let i = 0; i < 64; i++) acc.push(grainClock(lfsr, nfsr));

  const steps: Grain128StepState[] = [];

  const aadBits = bytesToBits(aad);
  for (let i = 0; i < aadBits.length; i++) {
    const y = grainClock(lfsr, nfsr);
    shiftSR(sr, aadBits[i]);
    updateAcc(acc, sr, y);
  }

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
    const ptBit = ctBits[i] ^ y;
    plaintextBits.push(ptBit);

    shiftSR(sr, ptBit);
    updateAcc(acc, sr, y);
  }

  const tagBytes = bitsToBytes(acc);
  const tag      = toHex(tagBytes);
  const valid    = !expectedTag || tag === expectedTag;

  return {
    ciphertext:   bitsToBytes(plaintextBits),
    keystream:    bitsToBytes(keystreamBits),
    tag,
    initialState: { ...initialState, acc: [...acc], sr: [...sr] },
    steps,
    valid,
  };
}
