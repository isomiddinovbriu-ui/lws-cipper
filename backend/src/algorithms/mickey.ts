/**
 * MICKEY-v2 (Mutual Irregular Clocking KE-generator) Stream Cipher
 * Based on the eSTREAM specification by Steve Babbage and Matthew Dodd
 * Key: 80 bits (10 bytes), IV: 0-80 bits (0-10 bytes)
 * Two registers: R (100 bits) and S (100 bits)
 */

export interface MickeyState {
  R: number[];  // 100-bit feedback shift register
  S: number[];  // 100-bit non-linear feedback shift register
}

export interface MickeyStepState {
  step: number;
  outputBit: number;
  rSlice: number[];
  sSlice: number[];
  controlBitR: number;
  controlBitS: number;
}

export interface MickeyResult {
  ciphertext: Uint8Array;
  keystream: Uint8Array;
  initialState: MickeyState;
  steps: MickeyStepState[];
}

// Companion sequence for S register (COMP0 and COMP1)
const COMP0 = [
  1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0,
  0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1,
  1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0,
  0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0,
  0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0,
];

const COMP1 = [
  1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1,
  0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0,
  0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0,
  1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1,
  0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1,
];

// Feedback taps for R (linear register with primitive polynomial)
// R uses the polynomial: x^100 + x^37 + 1 style clocking
const FB0 = [
  0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1,
  0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0,
  0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1,
  0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
  0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0,
];

const FB1 = [
  1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
  1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0,
  0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0,
  1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0,
  0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1,
];

function bytesToBits(bytes: Uint8Array): number[] {
  const bits: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    for (let b = 0; b < 8; b++) {
      bits.push((bytes[i] >> b) & 1);
    }
  }
  return bits;
}

/**
 * Clock the R register - linear feedback with control bit
 */
function clockR(R: number[], controlBit: number): void {
  // Compute feedback
let feedback = 0;
for (let i = 0; i < 100; i++) {
  feedback ^= R[i] & FB0[i];
}

  if (controlBit) {
    // XOR with FB1
    for (let i = 0; i < 100; i++) {
      feedback ^= R[i] & FB1[i];
    }
    feedback ^= 1; // inversion
  }

  // Shift register left
  for (let i = 99; i > 0; i--) R[i] = R[i - 1];
  R[0] = feedback;
}

/**
 * Clock the S register - non-linear feedback with companion sequences
 */
function clockS(S: number[], controlBit: number): void {
  const useComp1 = S[34];

  let fb = 0;
  for (let i = 0; i < 100; i++) {
    fb ^= S[i] & (useComp1 ? COMP1[i] : COMP0[i]);
  }

  if (controlBit) {
    for (let i = 0; i < 100; i++) {
      fb ^= S[i] & (useComp1 ? COMP0[i] : COMP1[i]);
    }
    fb ^= 1;
  }

  for (let i = 99; i > 0; i--) S[i] = S[i - 1];
  S[0] = fb;
}

/**
 * Single MICKEY-v2 clock cycle
 * Returns the output bit (R[99] XOR S[99] before clocking - use R[0] XOR S[0] for output)
 */
function mickeyClock(R: number[], S: number[], input = 0): number {
  const outputBit = R[99] ^ S[99];
  // Control bits for clocking
  const controlBitR = input ^ S[34];
  const controlBitS = input ^ R[67];

  clockR(R, controlBitR);
  clockS(S, controlBitS);

  return outputBit;
}

/**
 * Load key and IV bits into MICKEY-v2 via the clocking input mechanism
 */
function mickeyInit(key: Uint8Array, iv: Uint8Array): {
  R: number[];
  S: number[];
  initialState: MickeyState;
} {
  const R = new Array(100).fill(0);
  const S = new Array(100).fill(0);

  const ivBits = bytesToBits(iv);
  const keyBits = bytesToBits(key);

  // Load IV bits
  for (const bit of ivBits) {
    mickeyClock(R, S, bit);
  }

  // Load key bits
  for (const bit of keyBits) {
    mickeyClock(R, S, bit);
  }

  const initialState: MickeyState = {
    R: [...R],
    S: [...S],
  };

  return { R, S, initialState };
}

/**
 * Encrypt using MICKEY-v2
 */
export function mickeyEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  captureSteps = false,
  maxSteps = 64
): MickeyResult {
  if (key.length !== 10) throw new Error('MICKEY-v2 key must be 10 bytes (80 bits)');
  if (iv.length > 10) throw new Error('MICKEY-v2 IV must be at most 10 bytes (80 bits)');

  const { R, S, initialState } = mickeyInit(key, iv);

  const ciphertext = new Uint8Array(plaintext.length);
  const keystream = new Uint8Array(plaintext.length);
  const steps: MickeyStepState[] = [];

  for (let byteIdx = 0; byteIdx < plaintext.length; byteIdx++) {
    let ksByte = 0;
    for (let bitIdx = 0; bitIdx < 8; bitIdx++) {
      const globalStep = byteIdx * 8 + bitIdx;

      const controlBitR = S[34];
      const controlBitS = R[67];

      if (captureSteps && globalStep < maxSteps) {
        steps.push({
          step: globalStep,
          outputBit: R[0] ^ S[0],
          rSlice: R.slice(0, 8),
          sSlice: S.slice(0, 8),
          controlBitR,
          controlBitS,
        });
      }

      const z = mickeyClock(R, S, 0);
      ksByte |= z << bitIdx;
    }
    keystream[byteIdx] = ksByte;
    ciphertext[byteIdx] = plaintext[byteIdx] ^ ksByte;
  }

  return { ciphertext, keystream, initialState, steps };
}

export const mickeyDecrypt = mickeyEncrypt;
