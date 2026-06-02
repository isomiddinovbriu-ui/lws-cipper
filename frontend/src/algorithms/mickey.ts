export interface MickeyState {
  R: number[];
  S: number[];
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

const REGISTER_SIZE = 100;

const R_TAPS: number[] = [0, 26, 56, 91];
const S_TAPS_COMP0: number[] = [0, 50];
const S_TAPS_COMP1: number[] = [0, 47];

function bytesToBits(bytes: Uint8Array): number[] {
  const bits: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    for (let j = 7; j >= 0; j--) {
      bits.push((bytes[i] >> j) & 1);
    }
  }
  return bits;
}

function bitsToBytes(bits: number[]): Uint8Array {
  const bytes = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    bytes[Math.floor(i / 8)] |= bits[i] << (7 - (i % 8));
  }
  return bytes;
}

function calculateFeedbackR(R: number[], inputBit: number): number {
  let feedback = inputBit;
  for (const tap of R_TAPS) {
    feedback ^= R[tap];
  }
  return feedback;
}

function clockR(R: number[], inputBit: number, controlBit: number): void {
  const feedback = calculateFeedbackR(R, inputBit);
  for (let i = REGISTER_SIZE - 1; i > 0; i--) {
    R[i] = R[i - 1];
  }
  R[0] = feedback;
  if (controlBit === 1) {
    for (let i = 0; i < REGISTER_SIZE; i++) {
      R[i] ^= 1;
    }
  }
}

function calculateFeedbackS(S: number[], inputBit: number, controlBit: number): number {
  let feedback = inputBit;
  const taps = controlBit === 0 ? S_TAPS_COMP0 : S_TAPS_COMP1;
  for (const tap of taps) {
    feedback ^= S[tap];
  }
  return feedback;
}

function clockS(S: number[], inputBit: number, controlBit: number): void {
  const feedback = calculateFeedbackS(S, inputBit, controlBit);
  for (let i = REGISTER_SIZE - 1; i > 0; i--) {
    S[i] = S[i - 1];
  }
  S[0] = feedback;
}

function mickeyClock(R: number[], S: number[], inputBit: number = 0): number {
  const outputBit = R[0] ^ S[0];
  const controlBitR = S[34] ^ R[67];
  const controlBitS = S[67] ^ R[33];
  clockR(R, inputBit, controlBitR);
  clockS(S, inputBit, controlBitS);
  return outputBit;
}

function mickeyInit(key: Uint8Array, iv: Uint8Array): { R: number[]; S: number[]; initialState: MickeyState } {
  const R = new Array<number>(REGISTER_SIZE).fill(0);
  const S = new Array<number>(REGISTER_SIZE).fill(0);
  const ivBits = bytesToBits(iv);
  const keyBits = bytesToBits(key);
  for (const bit of ivBits) {
    mickeyClock(R, S, bit);
  }
  for (const bit of keyBits) {
    mickeyClock(R, S, bit);
  }
  for (let i = 0; i < 100; i++) {
    mickeyClock(R, S, 0);
  }
  const initialState: MickeyState = { R: [...R], S: [...S] };
  return { R, S, initialState };
}

function generateKeystream(R: number[], S: number[], length: number): Uint8Array {
  const keystreamBits: number[] = [];
  for (let i = 0; i < length * 8; i++) {
    const bit = mickeyClock(R, S, 0);
    keystreamBits.push(bit);
  }
  return bitsToBytes(keystreamBits);
}

export function mickeyEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  captureSteps: boolean = false,
  maxSteps: number = 64
): MickeyResult {
  if (key.length !== 10) throw new Error("MICKEY-128/80 key must be 80-bit (10 bytes)");
  if (iv.length < 8 || iv.length > 10) throw new Error("MICKEY-128/80 IV must be 64-80 bits (8-10 bytes)");
  const { R, S, initialState } = mickeyInit(key, iv);
  const R_copy = captureSteps ? [...R] : R;
  const S_copy = captureSteps ? [...S] : S;
  const workingR = captureSteps ? R_copy : R;
  const workingS = captureSteps ? S_copy : S;
  const keystream = generateKeystream(workingR, workingS, plaintext.length);
  const steps: MickeyStepState[] = [];
  if (captureSteps) {
    const R_step = [...initialState.R];
    const S_step = [...initialState.S];
    for (let step = 0; step < Math.min(maxSteps, plaintext.length * 8); step++) {
      const outputBit = R_step[0] ^ S_step[0];
      const controlBitR = S_step[34] ^ R_step[67];
      const controlBitS = S_step[67] ^ R_step[33];
      steps.push({ step, outputBit, rSlice: R_step.slice(0, 8), sSlice: S_step.slice(0, 8), controlBitR, controlBitS });
      mickeyClock(R_step, S_step, 0);
    }
  }
  const ciphertext = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) ciphertext[i] = plaintext[i] ^ keystream[i];
  return { ciphertext, keystream, initialState, steps };
}

export const mickeyDecrypt = mickeyEncrypt;
