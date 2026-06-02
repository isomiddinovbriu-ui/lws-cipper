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

/**
 * BIT HELPERS
 */
const getBit = (arr: Uint8Array, pos: number): number =>
  (arr[pos >> 3] >> (pos & 7)) & 1;

const setBit = (
  arr: Uint8Array,
  pos: number,
  val: number
): void => {
  if (val) {
    arr[pos >> 3] |= 1 << (pos & 7);
  } else {
    arr[pos >> 3] &= ~(1 << (pos & 7));
  }
};

/**
 * Shift register
 * bit(i+1) -> bit(i)
 */
function shiftRegister(
  reg: Uint8Array,
  size: number,
  newBit: number
) {
  for (let i = 0; i < size - 1; i++) {
    setBit(reg, i, getBit(reg, i + 1));
  }

  setBit(reg, size - 1, newBit);
}

/**
 * Trivium step (official spec)
 */
function triviumStep(
  a: Uint8Array,
  b: Uint8Array,
  c: Uint8Array
): number {
  // Output taps
  let t1 = getBit(a, 65) ^ getBit(a, 92);
  let t2 = getBit(b, 68) ^ getBit(b, 83);
  let t3 = getBit(c, 65) ^ getBit(c, 110);

  // keystream bit
  const z = t1 ^ t2 ^ t3;

  // feedback
  t1 ^= (getBit(a, 90) & getBit(a, 91)) ^ getBit(b, 77);
  t2 ^= (getBit(b, 81) & getBit(b, 82)) ^ getBit(c, 86);
  t3 ^= (getBit(c, 108) & getBit(c, 109)) ^ getBit(a, 68);

  shiftRegister(a, 93, t3);
  shiftRegister(b, 84, t1);
  shiftRegister(c, 111, t2);

  return z;
}

/**
 * Initialize registers
 *
 * A = key (80 bit) + 13 zeros
 * B = IV  (80 bit) + 4 zeros
 * C = 108 zeros + 111
 */
function initRegisters(
  key: Uint8Array,
  iv: Uint8Array
) {
  const a = new Uint8Array(12); // 93 bits
  const b = new Uint8Array(11); // 84 bits
  const c = new Uint8Array(14); // 111 bits

  // A <- key
  for (let i = 0; i < 80; i++) {
    setBit(a, i, getBit(key, i));
  }

  // B <- IV
  for (let i = 0; i < 80; i++) {
    setBit(b, i, getBit(iv, i));
  }

  // C[108..110] = 111
  setBit(c, 108, 1);
  setBit(c, 109, 1);
  setBit(c, 110, 1);

  return { a, b, c };
}

function registerToBits(
  reg: Uint8Array,
  size: number
): number[] {
  const out: number[] = [];

  for (let i = 0; i < size; i++) {
    out.push(getBit(reg, i));
  }

  return out;
}

/**
 * Encrypt / Decrypt
 */
export function triviumEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  captureSteps = false,
  maxSteps = 64
): TriviumResult {
  if (key.length !== 10) {
    throw new Error("Key 80-bit bo‘lishi kerak");
  }

  if (iv.length !== 10) {
    throw new Error("IV 80-bit bo‘lishi kerak");
  }

  const { a, b, c } =
    initRegisters(key, iv);

  const initialState: TriviumState = {
    registerA: registerToBits(a, 93),
    registerB: registerToBits(b, 84),
    registerC: registerToBits(c, 111),
  };

  /**
   * Warm-up: 4 × 288 = 1152
   */
  for (let i = 0; i < 1152; i++) {
    triviumStep(a, b, c);
  }

  const ciphertext =
    new Uint8Array(plaintext.length);

  const keystream =
    new Uint8Array(plaintext.length);

  const steps: TriviumStepState[] = [];

  for (let i = 0; i < plaintext.length; i++) {
    let ks = 0;

    for (let j = 0; j < 8; j++) {
      const step = i * 8 + j;

      const t1 =
        getBit(a, 65) ^
        getBit(a, 92);

      const t2 =
        getBit(b, 68) ^
        getBit(b, 83);

      const t3 =
        getBit(c, 65) ^
        getBit(c, 110);

      const z =
        triviumStep(a, b, c);

      if (
        captureSteps &&
        step < maxSteps
      ) {
        steps.push({
          step,
          bit: z,
          regA: registerToBits(a, 93),
          regB: registerToBits(b, 84),
          regC: registerToBits(c, 111),
          t1,
          t2,
          t3,
        });
      }

      ks |= z << j;
    }

    keystream[i] = ks;
    ciphertext[i] =
      plaintext[i] ^ ks;
  }

  return {
    ciphertext,
    keystream,
    initialState,
    steps,
  };
}

export const triviumDecrypt =
  triviumEncrypt;