/**
 * Ascon-AEAD128 Implementation
 * NIST Lightweight Cryptography standard (FIPS 202) asosida
 *
 * Parametrlar:
 *   Key:    128 bit (16 bayt)
 *   Nonce:  128 bit (16 bayt)
 *   State:  320 bit (5 × 64-bit so'z)
 *   Rate:   64 bit (8 bayt)
 *   rounds_a = 12,  rounds_b = 6
 *
 * TUZATILGAN XATOLAR:
 *   1. S-box oxirgi qadam: x1^=x0; x0^=x4; x3^=x2; x2=~x2
 *   2. Bayt tartibi: kichik-endian → katta-endian (Ascon spesifikatsiyasi talab qiladi)
 *   3. Buffer.from(...).toString('hex') → portativ toHex() funksiyasi (brauzer muvofiqligi)
 *   4. AAD bosqichida permutationSteps saqlanmay qolgan — tuzatildi
 *   5. Encryption bosqichida permutationSteps saqlanmay qolgan — tuzatildi
 *   6. Decryption finalization stateBefore noto'g'ri berilgan — tuzatildi
 *   7. Decryption so'nggi blokida state[0] yangilanishi noto'g'ri edi — tuzatildi
 */

// ─────────────────────────────────────────────
// Interfacelar
// ─────────────────────────────────────────────

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

// ─────────────────────────────────────────────
// Konstantalar
// ─────────────────────────────────────────────

/** Ascon tur konstantalari (12 tur uchun) */
const ROUND_CONSTANTS: bigint[] = [
  0xf0n, 0xe1n, 0xd2n, 0xc3n, 0xb4n, 0xa5n,
  0x96n, 0x87n, 0x78n, 0x69n, 0x5an, 0x4bn,
];

const MASK64 = 0xffffffffffffffffn;

// Ascon-128 uchun IV: key=128bit, rate=64bit, rounds_a=12, rounds_b=6
const IV_128 = 0x80400c0600000000n;

const RATE     = 8;   // 64 bit = 8 bayt
const ROUNDS_A = 12;
const ROUNDS_B = 6;

// ─────────────────────────────────────────────
// Yordamchi funksiyalar
// ─────────────────────────────────────────────

/** 64-bitli o'ngga aylantirish */
function rotr64(x: bigint, n: number): bigint {
  return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;
}

/**
 * Katta-endian baytlardan 64-bitli butun son yasash.
 * Ascon spesifikatsiyasi katta-endian tartibini talab qiladi.
 */
function bytesToBigInt(bytes: Uint8Array, offset: number, length = 8): bigint {
  let result = 0n;
  for (let i = 0; i < length; i++) {
    result = (result << 8n) | BigInt(bytes[offset + i] ?? 0);
  }
  return result & MASK64;
}

/**
 * 64-bitli butun sonni katta-endian baytlarga aylantirish.
 */
function bigIntToBytes(n: bigint, length = 8): Uint8Array {
  const result = new Uint8Array(length);
  let v = n & MASK64;
  for (let i = length - 1; i >= 0; i--) {
    result[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return result;
}

/**
 * Uint8Array-ni hex satrga aylantirish (Buffer ishlatmasdan — brauzer muvofiqligi).
 * FIX #3: Buffer.from().toString('hex') o'rniga portativ yechim.
 */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Hex satrni Uint8Array-ga aylantirish.
 */
function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, '').trim();
  if (clean.length % 2 !== 0) throw new Error('Noto\'g\'ri hex uzunligi');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ─────────────────────────────────────────────
// Ascon kriptografik qismlari
// ─────────────────────────────────────────────

/**
 * Ascon S-box: har 64-bitli ustun bo'yicha 5-bitli almashtirish.
 *
 * Bosqich 1: oldindan aralashtirish
 * Bosqich 2: nochiziqli almashtirish (NAND asosida)
 * Bosqich 3: keyingi aralashtirish (FIX #1 — avval noto'g'ri edi)
 *   To'g'ri: x1^=x0;  x0^=x4;  x3^=x2;  x2=~x2
 */
function sBox(
  x: [bigint, bigint, bigint, bigint, bigint],
): [bigint, bigint, bigint, bigint, bigint] {
  let [x0, x1, x2, x3, x4] = x;

  // Bosqich 1: oldindan aralashtirish
  x0 ^= x4; x4 ^= x3; x2 ^= x1;

  // Bosqich 2: nochiziqli almashtirish (t_i — eski qiymatlar)
  const t0 = x0, t1 = x1, t2 = x2, t3 = x3, t4 = x4;
  x0 = (t0 ^ (~t1 & t2)) & MASK64;
  x1 = (t1 ^ (~t2 & t3)) & MASK64;
  x2 = (t2 ^ (~t3 & t4)) & MASK64;
  x3 = (t3 ^ (~t4 & t0)) & MASK64;
  x4 = (t4 ^ (~t0 & t1)) & MASK64;

  // Bosqich 3: keyingi aralashtirish (spesifikatsiyaga mos)
  x1 = (x1 ^ x0) & MASK64;
  x0 = (x0 ^ x4) & MASK64;
  x3 = (x3 ^ x2) & MASK64;
  x2 = (~x2)     & MASK64;

  return [x0, x1, x2, x3, x4];
}

/**
 * Ascon chiziqli diffuziya qatlami.
 * Rotatsiya konstantalari spesifikatsiyadan olingan.
 */
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

/**
 * Bitta Ascon permutatsiya turi.
 * @param state    joriy holat
 * @param roundIdx tur indeksi (ROUND_CONSTANTS massivi indeksi)
 * @param capture  agar true bo'lsa oraliq holatlar qaytariladi
 */
function permRound(
  state: [bigint, bigint, bigint, bigint, bigint],
  roundIdx: number,
  capture: boolean,
): { state: [bigint, bigint, bigint, bigint, bigint]; step?: AsconPermutationStep } {
  const rc = ROUND_CONSTANTS[roundIdx];
  let s: [bigint, bigint, bigint, bigint, bigint] = [...state] as [bigint, bigint, bigint, bigint, bigint];

  // Tur konstantasini x2-ga qo'shish
  s[2] = (s[2] ^ rc) & MASK64;
  const afterRC = capture ? [...s] : [];

  // S-box
  s = sBox(s);
  const afterSBox = capture ? [...s] : [];

  // Chiziqli qatlam
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

/**
 * Ascon permutatsiyasini `rounds` marta qo'llash.
 *
 * @param state      joriy holat
 * @param rounds     turlar soni (p_a=12, p_b=6)
 * @param startRound birinchi tur uchun ROUND_CONSTANTS indeksi
 *                   p_a → 0,  p_b → ROUNDS_A - ROUNDS_B = 6
 * @param capture    oraliq holatlarni qaytarish
 */
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

// ─────────────────────────────────────────────
// To'ldirilgan bufer hosil qilish
// ─────────────────────────────────────────────

/**
 * Ascon-128 to'ldirish qoidasi: msg || 0x80 || 0x00...
 * Natija uzunligi RATE ning ko'paytmasi bo'ladi.
 */
function pad(data: Uint8Array): Uint8Array {
  const padded = new Uint8Array(Math.ceil((data.length + 1) / RATE) * RATE);
  padded.set(data);
  padded[data.length] = 0x80;
  return padded;
}

// ─────────────────────────────────────────────
// Ascon-128 shifrlash
// ─────────────────────────────────────────────

/**
 * Ascon-128 AEAD bilan shifrlash.
 *
 * @param plaintext   ochiq matn
 * @param key         128-bitli kalit (16 bayt)
 * @param nonce       128-bitli nonce  (16 bayt, takrorlanmasligi shart)
 * @param aad         qo'shimcha autentifikatsiya ma'lumoti (ixtiyoriy)
 * @param captureSteps oraliq holatlarni qaytarish (disk raskadrovka uchun)
 * @returns           shifrlangan matn, autentifikatsiya tegi va oraliq holatlar
 */
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

  // Boshlang'ich holat: IV || Kalit || Nonce
  let state: [bigint, bigint, bigint, bigint, bigint] = [IV_128, k0, k1, n0, n1];

  const initialState: AsconState = { x: [...state] as [bigint, bigint, bigint, bigint, bigint] };
  const steps: AsconStepState[] = [];

  // ── Boshlash: p_a, so'ng x3,x4 ga kalit XOR ──────────────────────────────
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

  // ── AAD qayta ishlash ─────────────────────────────────────────────────────
  if (aad.length > 0) {
    const paddedAAD = pad(aad);

    for (let i = 0; i < paddedAAD.length; i += RATE) {
      const block = bytesToBigInt(paddedAAD, i);
      const stateBefore = captureSteps ? [...state] as bigint[] : [];

      state[0] ^= block;

      // FIX #4: permSteps endi qaytariladi va step-ga qo'shiladi
      const { state: ns, steps: permSteps } = permutation(
        state, ROUNDS_B, ROUNDS_A - ROUNDS_B, captureSteps,
      );
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

  // Domen ajratish
  state[4] ^= 1n;

  // ── Shifrlash ─────────────────────────────────────────────────────────────
  const ciphertext = new Uint8Array(plaintext.length);
  const paddedPT   = pad(plaintext);

  for (let i = 0; i < paddedPT.length; i += RATE) {
    const block   = bytesToBigInt(paddedPT, i);
    const stateBefore = captureSteps ? [...state] as bigint[] : [];

    // Shifrlash: CT = S[0] XOR PT_block
    const ctWord  = (state[0] ^ block) & MASK64;
    state[0]      = ctWord;

    // Faqat haqiqiy baytlarni yozish (to'ldirish baytlarini emas)
    const ctBytes  = bigIntToBytes(ctWord);
    const writeLen = Math.min(RATE, plaintext.length - i);
    for (let j = 0; j < writeLen; j++) ciphertext[i + j] = ctBytes[j];

    const isLastBlock = (i + RATE >= paddedPT.length);

    // FIX #5: permSteps endi qaytariladi va step-ga qo'shiladi
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

  // ── Yakunlash: kalit XOR → p_a → kalit XOR ────────────────────────────────
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

  // Teg = x3 || x4  (128 bit)
  const tagBytes = new Uint8Array(16);
  tagBytes.set(bigIntToBytes(state[3]), 0);
  tagBytes.set(bigIntToBytes(state[4]), 8);

  // FIX #3: Buffer.from().toString('hex') o'rniga portativ toHex()
  return { ciphertext, tag: toHex(tagBytes), initialState, steps };
}

// ─────────────────────────────────────────────
// Ascon-128 shifrni ochish
// ─────────────────────────────────────────────

/**
 * Ascon-128 AEAD bilan shifrni ochish.
 *
 * @param ciphertext   shifrlangan matn
 * @param key          128-bitli kalit (16 bayt)
 * @param nonce        128-bitli nonce  (16 bayt)
 * @param aad          qo'shimcha autentifikatsiya ma'lumoti (ixtiyoriy)
 * @param expectedTag  kutilayotgan autentifikatsiya tegi (hex, ixtiyoriy)
 * @param captureSteps oraliq holatlarni qaytarish
 * @returns            ochiq matn, hisoblangan teg va tekshiruv natijasi
 */
export function asconDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  expectedTag?: string,
  captureSteps = false,
): AsconDecryptResult {
  if (key.length !== 16)   throw new Error('Kalit 16 bayt (128 bit) bo\'lishi kerak');
  if (nonce.length !== 16) throw new Error('Nonce 16 bayt (128 bit) bo\'lishi kerak');

  const k0 = bytesToBigInt(key,   0);
  const k1 = bytesToBigInt(key,   8);
  const n0 = bytesToBigInt(nonce, 0);
  const n1 = bytesToBigInt(nonce, 8);

  let state: [bigint, bigint, bigint, bigint, bigint] = [IV_128, k0, k1, n0, n1];
  const initialState: AsconState = { x: [...state] as [bigint, bigint, bigint, bigint, bigint] };
  const steps: AsconStepState[] = [];

  // ── Boshlash ──────────────────────────────────────────────────────────────
  {
    const { state: s1 } = permutation(state, ROUNDS_A, 0, false);
    state = s1;
    state[3] ^= k0;
    state[4] ^= k1;
  }

  // ── AAD qayta ishlash ─────────────────────────────────────────────────────
  if (aad.length > 0) {
    const paddedAAD = pad(aad);
    for (let i = 0; i < paddedAAD.length; i += RATE) {
      state[0] ^= bytesToBigInt(paddedAAD, i);
      const { state: ns } = permutation(state, ROUNDS_B, ROUNDS_A - ROUNDS_B, false);
      state = ns;
    }
  }

  // Domen ajratish
  state[4] ^= 1n;

  // ── Shifrni ochish ────────────────────────────────────────────────────────
  const plaintext = new Uint8Array(ciphertext.length);
  const paddedCT  = pad(ciphertext);

  for (let i = 0; i < paddedCT.length; i += RATE) {
    const ctWord  = bytesToBigInt(paddedCT, i);
    const ptWord  = (state[0] ^ ctWord) & MASK64;
    const ptBytes = bigIntToBytes(ptWord);

    const writeLen    = Math.min(RATE, ciphertext.length - i);
    for (let j = 0; j < writeLen; j++) plaintext[i + j] = ptBytes[j];

    const isLastBlock = (i + RATE >= paddedCT.length);

    if (isLastBlock) {
      // FIX #7: So'nggi blokda holat to'g'ri yangilanishi:
      // Shifrlashda state[0] = old_S XOR paddedPT, bu yerda ham shunday bo'lishi kerak.
      // paddedPT = ptBytes[0..writeLen-1] || 0x80 || 0x00...
      const paddedPTBlock = new Uint8Array(RATE);
      for (let j = 0; j < writeLen; j++) paddedPTBlock[j] = ptBytes[j];
      if (writeLen < RATE) paddedPTBlock[writeLen] = 0x80;
      // state[0] eski qiymati hali o'zgartirilmagan (loop boshida faqat ptWord hisoblandi)
      state[0] = (state[0] ^ bytesToBigInt(paddedPTBlock, 0)) & MASK64;
      // So'nggi blokda permutatsiya qo'llanilmaydi
    } else {
      // Shifrni ochishda CTni holatga qaytarish (Ascon spesifikatsiyasi)
      state[0] = ctWord;
      const { state: ns } = permutation(state, ROUNDS_B, ROUNDS_A - ROUNDS_B, false);
      state = ns;
    }
  }

  // ── Yakunlash ─────────────────────────────────────────────────────────────
  // FIX #6: stateBefore YAKUNLASHDAN OLDIN olinadi
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

  // Teg = x3 || x4  (128 bit)
  const tagBytes = new Uint8Array(16);
  tagBytes.set(bigIntToBytes(state[3]), 0);
  tagBytes.set(bigIntToBytes(state[4]), 8);
  const tag = toHex(tagBytes);

  // Teg tekshiruvi (vaqt-doimiy taqqoslash amalga oshirilmagan — ixtiyoriy yaxshilash)
  let valid = true;
  if (expectedTag !== undefined && expectedTag !== null) {
    const expected = expectedTag.replace(/^0x/i, '').trim().toLowerCase();
    valid = (tag === expected);
    if (!valid) {
      try { console.debug('[ascon] teg mos kelmadi', { hisoblangan: tag, kutilgan: expected }); }
      catch { /* jimlik */ }
    }
  }

  return { ciphertext: plaintext, tag, initialState, steps, valid };
}

// ─────────────────────────────────────────────
// Eksport qilingan yordamchi funksiyalar
// ─────────────────────────────────────────────

export { toHex, fromHex };

// ─────────────────────────────────────────────
// Tez sinov (ixtiyoriy — Node.js muhitida ishga tushiriladi)
// ─────────────────────────────────────────────

if (typeof process !== 'undefined' && process.argv[1]?.endsWith('ascon-aead128.ts')) {
  const key   = new Uint8Array(16).fill(0x00);  // Sinov kaliti (nollar)
  const nonce = new Uint8Array(16).fill(0x00);  // Sinov nonce  (nollar)
  const pt    = new TextEncoder().encode('Salom, Ascon!');
  const aad   = new TextEncoder().encode('test-aad');

  const { ciphertext, tag } = asconEncrypt(pt, key, nonce, aad);
  console.log('Shifrlangan:', toHex(ciphertext));
  console.log('Teg        :', tag);

  const { ciphertext: decrypted, valid } = asconDecrypt(ciphertext, key, nonce, aad, tag);
  console.log('Ochilgan   :', new TextDecoder().decode(decrypted));
  console.log('Teg to\'g\'ri:', valid);
}