/**
 * MICKEY-v2 (Mutual Irregular Clocking KE-generator) Stream Cipher
 * Based on the eSTREAM specification by Steve Babbage and Matthew Dodd
 * Key: 80 bits (10 bytes), IV: 0–80 bits (0–10 bytes)
 * Two registers: R (100 bits, linear) and S (100 bits, non-linear)
 *
 * Convention used throughout: RIGHT-SHIFT
 *   R[0] / S[0] = output end (oldest bit, first to leave)
 *   R[99] / S[99] = input end (newest bit)
 *   Each clock: bits move from R[99] toward R[0]
 *   Output bit = R[0] XOR S[0]  (sampled BEFORE clocking)
 */

export interface MickeyState {
  R: number[];  // 100-bit linear feedback shift register
  S: number[];  // 100-bit non-linear feedback shift register
}

export interface MickeyStepState {
  step:         number;
  outputBit:    number;
  rSlice:       number[];
  sSlice:       number[];
  controlBitR:  number;
  controlBitS:  number;
}

export interface MickeyResult {
  ciphertext:   Uint8Array;
  keystream:    Uint8Array;
  initialState: MickeyState;
  steps:        MickeyStepState[];
}

// ---------------------------------------------------------------------------
// Tap tables from the MICKEY-v2 eSTREAM specification
// ---------------------------------------------------------------------------

// Companion sequences for the S register (COMP0 / COMP1)
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

// Feedback taps for the R register (FB0 = normal clock, FB1 = alternate clock)
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bytesToBits(bytes: Uint8Array): number[] {
  const bits: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    for (let b = 0; b < 8; b++) {
      bits.push((bytes[i] >> b) & 1);
    }
  }
  return bits;
}

// ---------------------------------------------------------------------------
// Register clocking — Galois (element-wise) formulation
// ---------------------------------------------------------------------------

/**
 * Clock the R register (linear Galois LFSR, right-shift).
 *
 * FIX #2 — Previous version computed a single Fibonacci feedback bit (dot
 * product of the whole state with FB0/FB1), then did a left-shift.  The spec
 * applies feedback element-wise to each cell during the right-shift (Galois
 * style), which is what this implementation does.
 *
 *   FEEDBACK_BIT = R[0]  (the bit being shifted out)
 *   tap[i]       = FB0[i]        if CONTROL_BIT_R = 0
 *                = FB0[i]⊕FB1[i] if CONTROL_BIT_R = 1
 *   new_R[i]     = R[i+1] ⊕ (FEEDBACK_BIT & tap[i])   for i = 0..98
 *   new_R[99]    = FEEDBACK_BIT ⊕ CONTROL_BIT_R        (invert when ctrl=1)
 */
function clockR(R: number[], controlBit: number): void {
  const feedbackBit = R[0]; // output / oldest bit
  const newR        = new Array<number>(100);

  for (let i = 0; i < 99; i++) {
    const tap = controlBit ? (FB0[i] ^ FB1[i]) : FB0[i];
    newR[i]   = R[i + 1] ^ (feedbackBit & tap);
  }
  // New bit enters at position 99; invert when control bit is set
  newR[99] = feedbackBit ^ (controlBit ? 1 : 0);

  for (let i = 0; i < 100; i++) R[i] = newR[i];
}

/**
 * Clock the S register (non-linear companion-sequence Galois clock).
 *
 * FIX #3 — Previous version also collapsed everything into a single Fibonacci
 * feedback bit via dot products with COMP0/COMP1, then did a left-shift.
 * The correct Galois formulation applies the companion sequence element-wise
 * at each cell during the right-shift.
 *
 *   SEQ_BIT      = S[34]   (selects which companion is primary)
 *   FEEDBACK_BIT = S[0]    (bit being shifted out)
 *   comp         = COMP1   if SEQ_BIT = 1, else COMP0  (primary)
 *   compAlt      = COMP0   if SEQ_BIT = 1, else COMP1  (alternate)
 *   tap[i]       = comp[i]            if CONTROL_BIT_S = 0
 *                = comp[i] ⊕ compAlt[i]  if CONTROL_BIT_S = 1
 *   new_S[i]     = S[i+1] ⊕ (FEEDBACK_BIT & tap[i])   for i = 0..98
 *   new_S[99]    = FEEDBACK_BIT ⊕ CONTROL_BIT_S        (invert when ctrl=1)
 */
function clockS(S: number[], controlBit: number): void {
  const seqBit      = S[34];
  const feedbackBit = S[0]; // output / oldest bit
  const comp        = seqBit ? COMP1 : COMP0;
  const compAlt     = seqBit ? COMP0 : COMP1;

  const newS = new Array<number>(100);

  for (let i = 0; i < 99; i++) {
    const tap = controlBit ? (comp[i] ^ compAlt[i]) : comp[i];
    newS[i]   = S[i + 1] ^ (feedbackBit & tap);
  }
  newS[99] = feedbackBit ^ (controlBit ? 1 : 0);

  for (let i = 0; i < 100; i++) S[i] = newS[i];
}

// ---------------------------------------------------------------------------
// Core clock cycle
// ---------------------------------------------------------------------------

/**
 * One MICKEY-v2 clock cycle.
 *
 * FIX #1 (partial) — Output bit is R[0] ⊕ S[0] (the bits at the output /
 * oldest end of each register), sampled BEFORE the registers are advanced.
 * The previous version used R[99] ⊕ S[99] here (the input / newest end),
 * while the step-capture in mickeyEncrypt used R[0] ⊕ S[0] — contradictory.
 *
 * @param input  Extra input bit XOR'd into control bits (used during init).
 */
function mickeyClock(R: number[], S: number[], input = 0): number {
  // FIX #1: output sampled from the output end (index 0) before clocking
  const outputBit = R[0] ^ S[0];

  // Control bits: one register drives the other's clock
  const controlBitR = input ^ S[34];
  const controlBitS = input ^ R[67];

  clockR(R, controlBitR);
  clockS(S, controlBitS);

  return outputBit;
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/**
 * Load IV then key into MICKEY-v2 via the input-bit mechanism, producing the
 * post-init register states.
 */
function mickeyInit(key: Uint8Array, iv: Uint8Array): {
  R:            number[];
  S:            number[];
  initialState: MickeyState;
} {
  const R = new Array<number>(100).fill(0);
  const S = new Array<number>(100).fill(0);

  // IV bits loaded first, then key bits — each bit clocked in as INPUT_BIT
  for (const bit of bytesToBits(iv))  mickeyClock(R, S, bit);
  for (const bit of bytesToBits(key)) mickeyClock(R, S, bit);

  const initialState: MickeyState = { R: [...R], S: [...S] };
  return { R, S, initialState };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encrypt (or decrypt — stream cipher is symmetric) using MICKEY-v2.
 */
export function mickeyEncrypt(
  plaintext:   Uint8Array,
  key:         Uint8Array,
  iv:          Uint8Array,
  captureSteps = false,
  maxSteps     = 64
): MickeyResult {
  if (key.length !== 10) throw new Error('MICKEY-v2 key must be 10 bytes (80 bits)');
  if (iv.length > 10)    throw new Error('MICKEY-v2 IV must be at most 10 bytes (80 bits)');

  const { R, S, initialState } = mickeyInit(key, iv);

  const ciphertext = new Uint8Array(plaintext.length);
  const keystream  = new Uint8Array(plaintext.length);
  const steps: MickeyStepState[] = [];

  for (let byteIdx = 0; byteIdx < plaintext.length; byteIdx++) {
    let ksByte = 0;

    for (let bitIdx = 0; bitIdx < 8; bitIdx++) {
      const globalStep = byteIdx * 8 + bitIdx;

      // FIX #1 (complete): capture step state BEFORE clocking; output bit is
      // R[0] ⊕ S[0] — consistent with what mickeyClock() returns.
      // Previous code captured R[0]^S[0] here but mickeyClock returned
      // R[99]^S[99], creating an irreconcilable inconsistency.
      if (captureSteps && globalStep < maxSteps) {
        steps.push({
          step:        globalStep,
          outputBit:   R[0] ^ S[0],      // matches mickeyClock return value
          rSlice:      R.slice(0, 8),
          sSlice:      S.slice(0, 8),
          controlBitR: S[34],             // input=0 → controlBitR = 0 ^ S[34]
          controlBitS: R[67],             // input=0 → controlBitS = 0 ^ R[67]
        });
      }

      const z = mickeyClock(R, S, 0);    // input=0 during keystream generation
      ksByte |= z << bitIdx;
    }

    keystream[byteIdx]  = ksByte;
    ciphertext[byteIdx] = plaintext[byteIdx] ^ ksByte;
  }

  return { ciphertext, keystream, initialState, steps };
}

// Stream cipher: decryption is identical to encryption
export const mickeyDecrypt = mickeyEncrypt;