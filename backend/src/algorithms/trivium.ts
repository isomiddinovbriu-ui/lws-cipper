export interface TriviumState {
  registerA: number[];
  registerB: number[];
  registerC: number[];
}

export interface TriviumStepState {
  step: number;
  bit: number;
  regA: number[];
  regB: number[];
  regC: number[];
  t1: number;
  t2: number;
  t3: number;
}

export interface TriviumResult {
  ciphertext: Uint8Array;
  keystream: Uint8Array;
  initialState: TriviumState;
  steps: TriviumStepState[];
}

const getBit = (arr: Uint8Array, pos: number) =>
  (arr[pos >> 3] >> (pos & 7)) & 1;

const setBit = (arr: Uint8Array, pos: number, val: number) => {
  if (val) arr[pos >> 3] |= 1 << (pos & 7);
  else arr[pos >> 3] &= ~(1 << (pos & 7));
};

/**
 * SHIFT helper
 */
function shiftRight(reg: Uint8Array, size: number, newBit: number) {
  for (let i = 0; i < size - 1; i++) {
    const bit = getBit(reg, i + 1);
    setBit(reg, i, bit);
  }
  setBit(reg, size - 1, newBit);
}

/**
 * ✅ TO‘G‘RI TRIVIUM STEP
 */
function triviumStep(a: Uint8Array, b: Uint8Array, c: Uint8Array): number {
  // Output taps (correct spec mapping)
  const t1 = getBit(a, 65) ^ getBit(a, 92);
  const t2 = getBit(b, 68) ^ getBit(b, 83);
  const t3 = getBit(c, 65) ^ getBit(c, 110);

  const z = t1 ^ t2 ^ t3;

  // NON-LINEAR + feedback (FIXED!)
  const t1n = t1 ^ (getBit(a, 90) & getBit(a, 91)) ^ getBit(b, 77);
  const t2n = t2 ^ (getBit(b, 81) & getBit(b, 82)) ^ getBit(c, 86);
  const t3n = t3 ^ (getBit(c, 108) & getBit(c, 109)) ^ getBit(a, 68);

  shiftRight(a, 93, t3n);
  shiftRight(b, 84, t1n);
  shiftRight(c, 111, t2n);

  return z;
}

/**
 * INIT (TO‘G‘RI)
 */
function initRegisters(key: Uint8Array, iv: Uint8Array) {
  const a = new Uint8Array(12); // 93 bit
  const b = new Uint8Array(11); // 84 bit
  const c = new Uint8Array(14); // 111 bit

  // A ← key
  for (let i = 0; i < 80; i++) {
    setBit(a, i, (key[i >> 3] >> (i & 7)) & 1);
  }

  // B = 0

  // C ← IV
  for (let i = 0; i < 80; i++) {
    setBit(c, i, (iv[i >> 3] >> (i & 7)) & 1);
  }

  // C[108..110] = 1
  setBit(c, 108, 1);
  setBit(c, 109, 1);
  setBit(c, 110, 1);

  return { a, b, c };
}

/**
 * ENCRYPT / DECRYPT
 */
export function triviumEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  captureSteps = false,
  maxSteps = 64
): TriviumResult {
  if (key.length !== 10) throw new Error("Key 80-bit bo‘lishi kerak");
  if (iv.length !== 10) throw new Error("IV 80-bit bo‘lishi kerak");

  const { a, b, c } = initRegisters(key, iv);

  const initialState: TriviumState = {
    registerA: Array.from(a),
    registerB: Array.from(b),
    registerC: Array.from(c),
  };

  // Warm-up
  for (let i = 0; i < 1152; i++) {
    triviumStep(a, b, c);
  }

  const ciphertext = new Uint8Array(plaintext.length);
  const keystream = new Uint8Array(plaintext.length);
  const steps: TriviumStepState[] = [];

  for (let i = 0; i < plaintext.length; i++) {
    let ks = 0;

    for (let j = 0; j < 8; j++) {
      const step = i * 8 + j;

      const t1 = getBit(a, 65) ^ getBit(a, 92);
      const t2 = getBit(b, 68) ^ getBit(b, 83);
      const t3 = getBit(c, 65) ^ getBit(c, 110);

      if (captureSteps && step < maxSteps) {
        steps.push({
          step,
          bit: t1 ^ t2 ^ t3,
          regA: Array.from(a.slice(0, 4)),
          regB: Array.from(b.slice(0, 4)),
          regC: Array.from(c.slice(0, 4)),
          t1,
          t2,
          t3,
        });
      }

      const z = triviumStep(a, b, c);
      ks |= z << j;
    }

    keystream[i] = ks;
    ciphertext[i] = plaintext[i] ^ ks;
  }

  return { ciphertext, keystream, initialState, steps };
}

export const triviumDecrypt = triviumEncrypt;