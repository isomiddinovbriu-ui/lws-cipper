/**
 * Trivium Stream Cipher Implementation
 * Based on the eSTREAM specification by De Cannière and Preneel
 * Key: 80 bits (10 bytes), IV: 80 bits (10 bytes)
 * State: 288 bits split across 3 shift registers (93 + 84 + 111 bits)
 */

export interface TriviumState {
  registerA: number[];  // 93 bits
  registerB: number[];  // 84 bits
  registerC: number[];  // 111 bits
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
  tag?: string;
}

function getBit(arr: number[], pos: number): number {
  return (arr[pos >> 3] >> (pos & 7)) & 1;
}

function setBit(arr: number[], pos: number, val: number): void {
  if (val) {
    arr[pos >> 3] |= 1 << (pos & 7);
  } else {
    arr[pos >> 3] &= ~(1 << (pos & 7));
  }
}

/**
 * Initialize Trivium state with key and IV
 * Per spec: load key into s1[0..79], IV into s3[0..79], set s3[108..110]=1
 */
function initTrivium(key: Uint8Array, iv: Uint8Array): { s: Uint8Array; initialState: TriviumState } {
  // Full state as 36-byte (288-bit) array
  const s = new Uint8Array(36);

  // Load key into bits 0..79 (first 10 bytes)
  for (let i = 0; i < 10; i++) s[i] = key[i];

  // Bits 80..92 remain zero (s1 fills 0..92)

  // Load IV into s3 portion: bits 177..256 (s3 starts at bit 177)
  // s2 occupies bits 93..176, s3 occupies bits 177..287
  for (let i = 0; i < 10; i++) {
    const bytePos = (177 + i * 8) >> 3;
    const bitOff = (177 + i * 8) & 7;
    for (let b = 0; b < 8; b++) {
      const bit = (iv[i] >> b) & 1;
      const globalBit = 177 + i * 8 + b;
      setBit(Array.from(s), globalBit, bit);
    }
  }

  // Simpler approach: use separate register arrays
  const regA = new Uint8Array(12); // 93 bits -> 12 bytes
  const regB = new Uint8Array(11); // 84 bits -> 11 bytes
  const regC = new Uint8Array(14); // 111 bits -> 14 bytes

  // Load key into register A bits 0..79
  for (let i = 0; i < 10; i++) regA[i] = key[i];

  // Load IV into register C bits 0..79
  for (let i = 0; i < 10; i++) regC[i] = iv[i];

  // Set bits 108, 109, 110 of register C to 1
  regC[13] = 0b00000111; // bits 104-111, so bits 108,109,110 -> positions 4,5,6

  const captureInitial = (): TriviumState => ({
    registerA: Array.from(regA),
    registerB: Array.from(regB),
    registerC: Array.from(regC),
  });

  const initialState = captureInitial();

  // Run 4 * 288 = 1152 warm-up rounds
  for (let i = 0; i < 1152; i++) {
    triviumStep(regA, regB, regC);
  }

  return { s: new Uint8Array(36), initialState };
}

/**
 * Single clock step of Trivium - mutates registers in place, returns output bit
 * Register sizes: A=93, B=84, C=111
 * Feedback taps (1-indexed per spec -> 0-indexed here):
 *   t1 = s[66] ^ s[93]   -> A[65] ^ A[92]  (but A is 93 bits, indices 0..92)
 *   t2 = s[162] ^ s[177] -> B[84-93=?]... let's use the standard formulation
 */
function triviumStep(a: Uint8Array, b: Uint8Array, c: Uint8Array): number {
  // Tap positions (0-indexed in each register):
  // t1 = a[65] XOR a[92]  -- output + feedback for A
  // t2 = b[68] XOR b[83]  -- output + feedback for B  
  // t3 = c[65] XOR c[110] -- output + feedback for C
  const getBit8 = (arr: Uint8Array, pos: number) => (arr[pos >> 3] >> (pos & 7)) & 1;

  const t1 = getBit8(a, 65) ^ getBit8(a, 92);
  const t2 = getBit8(b, 68) ^ getBit8(b, 83);
  const t3 = getBit8(c, 65) ^ getBit8(c, 110);

  const z = t1 ^ t2 ^ t3; // keystream bit

  // Compute new feedback bits
  const fb1 = t3 ^ (getBit8(c, 108) & getBit8(c, 109)) ^ getBit8(a, 0);
  const fb2 = t1 ^ (getBit8(a, 90) & getBit8(a, 91)) ^ getBit8(b, 0);
  const fb3 = t2 ^ (getBit8(b, 81) & getBit8(b, 82)) ^ getBit8(c, 0);

  // Shift registers right (bit 0 is oldest, we shift in from the high end)
  // Shift A: bits 1..92 -> 0..91, new bit at 92
  shiftRegisterRight(a, 93, fb2);
  shiftRegisterRight(b, 84, fb3);
  shiftRegisterRight(c, 111, fb1);

  return z;
}

function shiftRegisterRight(reg: Uint8Array, bits: number, newBit: number): void {
  // Shift all bits right by 1 (bit 0 drops out, new bit enters at position bits-1)
  let carry = newBit;
  for (let i = bits - 1; i >= 0; i--) {
    const byteIdx = i >> 3;
    const bitIdx = i & 7;
    const current = (reg[byteIdx] >> bitIdx) & 1;
    if (carry) reg[byteIdx] |= 1 << bitIdx;
    else reg[byteIdx] &= ~(1 << bitIdx);
    carry = current;
  }
}

/**
 * Encrypt/decrypt data using Trivium (XOR with keystream)
 */
export function triviumEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  captureSteps = false,
  maxSteps = 64
): TriviumResult {
  if (key.length !== 10) throw new Error('Trivium key must be 10 bytes (80 bits)');
  if (iv.length !== 10) throw new Error('Trivium IV must be 10 bytes (80 bits)');

  const regA = new Uint8Array(12);
  const regB = new Uint8Array(11);
  const regC = new Uint8Array(14);

  // Load key into A[0..79]
  for (let i = 0; i < 10; i++) regA[i] = key[i];

  // Load IV into C[0..79]
  for (let i = 0; i < 10; i++) regC[i] = iv[i];

  // Set C[108] = C[109] = C[110] = 1
  regC[13] = 0b00000111;

  const initialState: TriviumState = {
    registerA: Array.from(regA),
    registerB: Array.from(regB),
    registerC: Array.from(regC),
  };

  // Warm-up: 1152 rounds
  for (let i = 0; i < 1152; i++) {
    triviumStep(regA, regB, regC);
  }

  const ciphertext = new Uint8Array(plaintext.length);
  const keystream = new Uint8Array(plaintext.length);
  const steps: TriviumStepState[] = [];

  const getBit8 = (arr: Uint8Array, pos: number) => (arr[pos >> 3] >> (pos & 7)) & 1;

  // Generate keystream byte by byte
  for (let byteIdx = 0; byteIdx < plaintext.length; byteIdx++) {
    let ksByte = 0;
    for (let bitIdx = 0; bitIdx < 8; bitIdx++) {
      const globalStep = byteIdx * 8 + bitIdx;

      // Capture step state before clocking (for visualization)
      if (captureSteps && globalStep < maxSteps) {
        const t1 = getBit8(regA, 65) ^ getBit8(regA, 92);
        const t2 = getBit8(regB, 68) ^ getBit8(regB, 83);
        const t3 = getBit8(regC, 65) ^ getBit8(regC, 110);
        steps.push({
          step: globalStep,
          bit: t1 ^ t2 ^ t3,
          regA: Array.from(regA.slice(0, 4)),
          regB: Array.from(regB.slice(0, 4)),
          regC: Array.from(regC.slice(0, 4)),
          t1,
          t2,
          t3,
        });
      }

      const z = triviumStep(regA, regB, regC);
      ksByte |= z << bitIdx;
    }
    keystream[byteIdx] = ksByte;
    ciphertext[byteIdx] = plaintext[byteIdx] ^ ksByte;
  }

  return { ciphertext, keystream, initialState, steps };
}

export const triviumDecrypt = triviumEncrypt;
