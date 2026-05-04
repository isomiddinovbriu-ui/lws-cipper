import { useState, useEffect } from 'react';
import { getAlgorithms, Algorithm } from '../services/api';
import clsx from 'clsx';

const DETAILS: Record<string, { internals: string; diagram: string[]; security: string }> = {
  trivium: {
    internals: "Uchta siljish registri (A=93, B=84, C=111 bit) — jami 288 bit. Har bir siklda uch registrdagi tegishli bitlarning XOR orqali bitta keystream biti hosil bo'ladi. Noqonuniy feedback XORdan oldin ketma-ket bitlarning AND operatsiyasini o'z ichiga oladi.",
    diagram: [
      'Holat: [A: 93 bit] [B: 84 bit] [C: 111 bit]',
      "Har qadam: t1=A[65]⊕A[92], t2=B[68]⊕B[83], t3=C[65]⊕C[110]",
      'Chiqish: z = t1 ⊕ t2 ⊕ t3',
      'Feedback: fb1=t3⊕(C[108]&C[109])⊕A[0]',
      'Ishga tushirish: 4×288 = 1152 sikl',
    ],
    security: "80-bit kalit. Amaliy hujumlar ma'lum emas. Aparat uchun samarali, IoT uchun mos.",
  },
  grain128aead: {
    internals: "Ikki registr: 128-bit LFSR va 128-bit NFSR. Init davomida pre-output keystream ikkala registrga ham qaytariladi. AEAD operatsiyalarida autentifikatsiya accumulator va shift registr orqali amalga oshiriladi.",
    diagram: [
      'LFSR: x^128 + x^7 + x^38 + x^70 + x^81 + x^96 + 1',
      'NFSR: nonlinear h(b,s) feedback polinomi',
      'Chiqish: y = h(b[12], s[8], s[13]...)',
      'TAG: 64-bit accumulator ⊕ keystream·plaintext',
      'Ishga tushirish: 256 warmup sikl',
    ],
    security: "128-bit xavfsizlik. NIST Lightweight Cryptography finalisti. 64-bit autentifikatsiya tegi taqdim etadi.",
  },
  mickey: {
    internals: "Ikki 100-bit registr (R — linear, S — nonlinear) nazorat bitlari asosida noma'lum soat bilan ishlaydi. O'zaro noma'lum soatlash algebraik hujumlarga qarshi chidamlilik beradi.",
    diagram: [
      'R: linear feedback (FB0/FB1 polinomi)',
      'S: nonlinear clocking (COMP0/COMP1 ketma-ketliklari)',
      'Control_R = input ⊕ S[34]',
      'Control_S = input ⊕ R[67]',
      'Chiqish: R[0] ⊕ S[0]',
    ],
    security: "80-bit xavfsizlik. Algebraik va korrelyatsiyaga qarshi himoyalangan, apparat uchun optimallashtirilgan.",
  },
  chacha20: {
    internals: "ARX (Add-Rotate-XOR) dizayni. 4×4 matrisa (32-bit so'zlar) 20 tur kvoter-round operatsiyalari bilan qayta ishlanadi. 64-baytli keystream bloklari hosil bo'ladi. Parallel ishlash uchun counter asosida.",
    diagram: [
      'Holat: [constants(4)] [key(8)] [counter(1)] [nonce(3)] = 16×32bit',
      'Quarter Round: a+=b; d^=a; d<<<16; c+=d; b^=c; b<<<12; ...',
      '10 ustunli + 10 diagonal round = jami 20',
      'Final: working_state + initial_state (add-back)',
      'Blok hajmi: 64 bayt, har blokda counter oshadi',
    ],
    security: "256-bit kalit. Salsa20 ning davomchisi. TLS 1.3, SSH, WireGuard da qo'llanadi.",
  },
  ascon: {
    internals: "Sponge asosidagi AEAD, 320-bit holat (5×64-bit so'z). Ascon permutatsiyasi konstant qo'shish, S-box va chiziqli diffuziya qatlamlarini qo'llaydi. Rate=64 bit, capacity=256 bit.",
    diagram: [
      'Holat: [x0][x1][x2][x3][x4] = 5×64-bit so‘z',
      'p_a (12 round) — init/finalize uchun',
      'p_b (6 round) — har bir AAD/plaintext blok uchun',
      'S-box: ustun bo‘yicha 5-bit nonlinear transform',
      "Linear: xᵢ = xᵢ ⊕ rot(xᵢ, r₁) ⊕ rot(xᵢ, r₂)",
      'TAG: finalizatsiyadan keyin x3||x4',
    ],
    security: "NIST Lightweight Cryptography standarti (NIST SP 800-232). 128-bit kalit + 128-bit nonce.",
  },
};

const TYPE_COLORS: Record<string, string> = {
  'Stream Cipher': 'badge-blue',
  'AEAD Stream Cipher': 'badge-green',
  'AEAD': 'badge-purple',
};

export default function AlgorithmsPage() {
  const [algorithms, setAlgorithms] = useState<Algorithm[]>([]);
  const [selected, setSelected] = useState<string>('trivium');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAlgorithms()
      .then(res => { setAlgorithms(res.data); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const algo = algorithms.find(a => a.id === selected);
  const detail = DETAILS[selected];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-slate-100 mb-2">🧬 Algoritmlar</h1>
        <p className="text-slate-400">Har bir shifrning texnik tafsilotlari, ichki tuzilishi va xavfsizlik xususiyatlari</p>
      </div>

      {loading ? (
        <div className="card flex items-center justify-center py-20">
          <span className="text-slate-500 animate-pulse">Yuklanmoqda...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-8">
          {/* Algorithm list */}
          <div className="space-y-2">
            {algorithms.map(a => (
              <button
                key={a.id}
                onClick={() => setSelected(a.id)}
                className={clsx(
                  'w-full text-left p-4 rounded-xl border transition-all duration-200',
                  selected === a.id
                    ? 'border-primary-500 bg-primary-500/10 shadow-lg shadow-primary-500/10'
                    : 'border-slate-700/50 bg-dark-800/50 hover:border-slate-600'
                )}
              >
                <div className="font-semibold text-slate-200">{a.name}</div>
                <div className="flex items-center gap-2 mt-1">
                  <span className={TYPE_COLORS[a.type] ?? 'badge-blue'}>{a.type}</span>
                </div>
                <div className="text-slate-500 text-xs mt-1">{a.family}</div>
              </button>
            ))}
          </div>

          {/* Detail panel */}
          {algo && detail && (
            <div className="xl:col-span-3 space-y-6">
              {/* Header */}
              <div className="card">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h2 className="text-2xl font-bold text-slate-100">{algo.name}</h2>
                    <div className="flex items-center gap-2 mt-2">
                      <span className={TYPE_COLORS[algo.type] ?? 'badge-blue'}>{algo.type}</span>
                      <span className="badge-amber">{algo.family}</span>
                      {algo.isAEAD && <span className="badge-purple">AEAD</span>}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-slate-400 text-sm">IoT uchun moslik</div>
                    <div className={clsx(
                      'font-semibold',
                      algo.iotSuitability === 'Excellent' ? 'text-emerald-300'
                      : algo.iotSuitability === 'Good' ? 'text-blue-300'
                      : 'text-amber-300'
                    )}>
                      {algo.iotSuitability}
                    </div>
                  </div>
                </div>

                    <p className="text-slate-300 leading-relaxed">{algo.description}</p>
              </div>

              {/* Params */}
              <div className="grid grid-cols-3 gap-4">
                  {[
                  { label: "Kalit o'lchami", value: `${algo.keyBits} bits`, sub: `${algo.keyBits / 8} bytes / ${algo.keyBits / 4} hex chars` },
                  { label: "Nonce o'lchami", value: `${algo.nonceBits} bits`, sub: `${algo.nonceBits / 8} bytes / ${algo.nonceBits / 4} hex chars` },
                  { label: 'Autentifikatsiya tegi', value: algo.isAEAD ? '64–128 bits' : 'N/A', sub: algo.isAEAD ? "Autentifikatsiyalangan shifrlash" : "Faqat oqim shifri" },
                ].map(p => (
                  <div key={p.label} className="card text-center bg-dark-900/60">
                    <div className="text-primary-300 font-bold text-xl">{p.value}</div>
                    <div className="text-slate-400 text-sm mt-1">{p.label}</div>
                    <div className="text-slate-600 text-xs mt-1">{p.sub}</div>
                  </div>
                ))}
              </div>

              {/* Internals */}
              <div className="card">
                <h3 className="section-title mb-4 text-lg">⚙️ Ichki tuzilma</h3>
                <p className="text-slate-300 text-sm leading-relaxed mb-4">{detail.internals}</p>

                <div className="bg-dark-950/60 border border-slate-700/40 rounded-xl p-4">
                  <div className="text-slate-500 text-xs font-semibold mb-3 uppercase tracking-wide">Ishlash jarayoni</div>
                  <div className="space-y-2">
                    {detail.diagram.map((line, i) => (
                      <div key={i} className="flex gap-3 text-sm font-mono">
                        <span className="text-slate-600 shrink-0">{String(i + 1).padStart(2, '0')}</span>
                        <span className="text-slate-300">{line}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Security */}
              <div className="card">
                <h3 className="section-title mb-4 text-lg">🔐 Xavfsizlik xususiyatlari</h3>
                <p className="text-slate-300 text-sm leading-relaxed">{detail.security}</p>
              </div>

              {/* Strengths */}
              <div className="card">
                <h3 className="section-title mb-4 text-lg">✅ Kuchli tomonlari</h3>
                <div className="space-y-2">
                  {algo.strengths.map((s, i) => (
                    <div key={i} className="flex items-center gap-3 text-sm text-slate-300">
                      <span className="w-5 h-5 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 text-xs shrink-0">✓</span>
                      {s}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
