import { useState, useEffect } from 'react';
import { getAlgorithms, Algorithm } from '../services/api';
import clsx from 'clsx';

const DETAILS: Record<string, { internals: string; diagram: string[]; security: string }> = {
  trivium: {
    internals: 'Three shift registers (A=93, B=84, C=111 bits) totaling 288 bits. Each clock produces 1 keystream bit via XOR of tap bits from all three registers. Nonlinear feedback involves AND of consecutive bits before XOR.',
    diagram: [
      'State: [A: 93 bits] [B: 84 bits] [C: 111 bits]',
      'Each step: t1=A[65]⊕A[92], t2=B[68]⊕B[83], t3=C[65]⊕C[110]',
      'Output: z = t1 ⊕ t2 ⊕ t3',
      'Feedback: fb1=t3⊕(C[108]&C[109])⊕A[0]',
      'Warmup: 4×288 = 1152 rounds',
    ],
    security: '80-bit key size. No known practical attacks. Hardware-efficient, suitable for IoT.',
  },
  grain128aead: {
    internals: 'Two linear registers: 128-bit LFSR and 128-bit NFSR. Pre-output keystream feeds back into both during init. Authentication via accumulator and shift register updated during AEAD operations.',
    diagram: [
      'LFSR: x^128 + x^7 + x^38 + x^70 + x^81 + x^96 + 1',
      'NFSR: nonlinear h(b,s) feedback polynomial',
      'Output: y = h(b[12], s[8], s[13]...)',
      'TAG: 64-bit via accumulator ⊕ keystream·plaintext',
      'Initialization: 256 warmup rounds',
    ],
    security: '128-bit security. NIST Lightweight Cryptography finalist. Provides 64-bit authentication tag.',
  },
  mickey: {
    internals: 'Two 100-bit registers (R linear, S nonlinear) clocked irregularly using control bits derived from register states. Mutual irregular clocking provides resistance to algebraic attacks.',
    diagram: [
      'R: linear feedback with FB0/FB1 polynomial selection',
      'S: nonlinear clocking via COMP0/COMP1 sequences',
      'Control_R = input ⊕ S[34]',
      'Control_S = input ⊕ R[67]',
      'Output: R[0] ⊕ S[0]',
    ],
    security: '80-bit security. Designed to resist algebraic and correlation attacks. Hardware-optimized.',
  },
  chacha20: {
    internals: 'ARX design (Add-Rotate-XOR). 4×4 matrix of 32-bit words processed by 20 rounds of quarter-round operations. Generates 64-byte keystream blocks. Counter-based for parallel processing.',
    diagram: [
      'State: [constants(4)] [key(8)] [counter(1)] [nonce(3)] = 16×32bit',
      'Quarter Round: a+=b; d^=a; d<<<16; c+=d; b^=c; b<<<12; ...',
      '10 column rounds + 10 diagonal rounds = 20 total',
      'Final: working_state + initial_state (add-back)',
      'Block size: 64 bytes, counter increments per block',
    ],
    security: '256-bit key. Successor to Salsa20. Deployed in TLS 1.3, SSH, WireGuard.',
  },
  ascon: {
    internals: 'Sponge-based AEAD using 320-bit state (5×64-bit words). Ascon permutation applies constant-add, S-box, and linear diffusion layers. Rate=64 bits, capacity=256 bits.',
    diagram: [
      'State: [x0][x1][x2][x3][x4] = 5×64-bit words',
      'p_a (12 rounds) for init/finalize',
      'p_b (6 rounds) for each AAD/plaintext block',
      'S-box: 5-bit nonlinear transform applied column-wise',
      'Linear: xᵢ = xᵢ ⊕ rot(xᵢ, r₁) ⊕ rot(xᵢ, r₂)',
      'TAG: x3||x4 after finalization',
    ],
    security: 'NIST Lightweight Cryptography Standard (NIST SP 800-232). 128-bit key + 128-bit nonce.',
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
        <h1 className="text-3xl font-bold text-slate-100 mb-2">🧬 Algorithms</h1>
        <p className="text-slate-400">Technical details, internals, and security properties of each cipher</p>
      </div>

      {loading ? (
        <div className="card flex items-center justify-center py-20">
          <span className="text-slate-500 animate-pulse">Loading...</span>
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
                    <div className="text-slate-400 text-sm">IoT Suitability</div>
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
                  { label: 'Key Size', value: `${algo.keyBits} bits`, sub: `${algo.keyBits / 8} bytes / ${algo.keyBits / 4} hex chars` },
                  { label: 'Nonce Size', value: `${algo.nonceBits} bits`, sub: `${algo.nonceBits / 8} bytes / ${algo.nonceBits / 4} hex chars` },
                  { label: 'Auth Tag', value: algo.isAEAD ? '64–128 bits' : 'N/A', sub: algo.isAEAD ? 'Authenticated encryption' : 'Stream cipher only' },
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
                <h3 className="section-title mb-4 text-lg">⚙️ Internal Structure</h3>
                <p className="text-slate-300 text-sm leading-relaxed mb-4">{detail.internals}</p>

                <div className="bg-dark-950/60 border border-slate-700/40 rounded-xl p-4">
                  <div className="text-slate-500 text-xs font-semibold mb-3 uppercase tracking-wide">Operational Flow</div>
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
                <h3 className="section-title mb-4 text-lg">🔐 Security Properties</h3>
                <p className="text-slate-300 text-sm leading-relaxed">{detail.security}</p>
              </div>

              {/* Strengths */}
              <div className="card">
                <h3 className="section-title mb-4 text-lg">✅ Strengths</h3>
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
