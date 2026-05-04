import { Link } from 'react-router-dom';

const features = [
  {
    icon: '🔒',
    title: 'Multi-Algorithm Encryption',
    desc: 'Encrypt text and files using 5 lightweight ciphers simultaneously. Compare outputs side by side.',
    color: 'from-primary-500 to-primary-700',
  },
  {
    icon: '🔓',
    title: 'Decryption & Verification',
    desc: 'Decrypt ciphertext with AEAD authentication tag verification for Grain-128AEAD and Ascon.',
    color: 'from-emerald-500 to-emerald-700',
  },
  {
    icon: '📊',
    title: 'Performance Benchmarks',
    desc: 'Measure throughput, latency, and memory usage. Visual charts with comparison radar.',
    color: 'from-accent-500 to-accent-700',
  },
  {
    icon: '🔬',
    title: 'Step-by-Step Visualization',
    desc: 'Inspect internal cipher state changes: shift registers, quarter rounds, permutation steps.',
    color: 'from-amber-500 to-amber-700',
  },
  {
    icon: '💾',
    title: 'Export Everything',
    desc: 'Download results as TXT reports, JSON, CSV. Save encrypted files as .enc binaries.',
    color: 'from-rose-500 to-rose-700',
  },
  {
    icon: '🔐',
    title: 'AEAD Authentication',
    desc: 'Full Authenticated Encryption with Associated Data for Grain-128AEAD and Ascon-AEAD128.',
    color: 'from-indigo-500 to-indigo-700',
  },
];

const algorithms = [
  { name: 'Trivium', badge: 'eSTREAM', color: 'badge-blue', desc: '80-bit key · 288-bit state' },
  { name: 'Grain-128AEAD', badge: 'NIST LWC', color: 'badge-green', desc: '128-bit key · LFSR+NFSR' },
  { name: 'MICKEY-v2', badge: 'eSTREAM', color: 'badge-blue', desc: '80-bit key · Irregular clocking' },
  { name: 'ChaCha20', badge: 'RFC 7539', color: 'badge-amber', desc: '256-bit key · ARX design' },
  { name: 'Ascon-AEAD128', badge: 'NIST Standard', color: 'badge-purple', desc: '128-bit key · Sponge AEAD' },
];

export default function HomePage() {
  return (
    <div className="space-y-16">
      {/* Hero */}
      <div className="text-center py-12">
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary-500/10 border border-primary-500/30 text-primary-300 text-sm font-medium mb-8">
          <span className="w-2 h-2 rounded-full bg-primary-400 animate-pulse-slow"></span>
          Production-Ready Cryptographic Analysis Platform
        </div>

        <h1 className="text-5xl md:text-6xl font-bold mb-6 leading-tight">
          <span className="text-gradient">Lightweight Cipher</span>
          <br />
          <span className="text-slate-100">Analysis Suite</span>
        </h1>

        <p className="text-xl text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed">
          Encrypt, decrypt, and benchmark 5 NIST/eSTREAM lightweight cryptographic algorithms.
          Visualize internal state and compare performance metrics in real time.
        </p>

        <div className="flex flex-wrap justify-center gap-4">
          <Link to="/encrypt" className="btn-primary text-base px-8 py-3">
            🔒 Start Encrypting
          </Link>
          <Link to="/benchmark" className="btn-secondary text-base px-8 py-3">
            📊 Run Benchmarks
          </Link>
          <Link to="/algorithms" className="btn-ghost text-base px-8 py-3">
            🧬 View Algorithms →
          </Link>
        </div>
      </div>

      {/* Algorithm Pills */}
      <div className="card">
        <h2 className="section-title mb-6">
          <span>🧬</span> Supported Algorithms
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {algorithms.map(algo => (
            <div key={algo.name} className="bg-dark-900/60 border border-slate-700/50 rounded-lg p-4 text-center hover:border-primary-500/50 transition-colors">
              <div className="font-semibold text-slate-200 mb-1">{algo.name}</div>
              <span className={algo.color}>{algo.badge}</span>
              <p className="text-slate-500 text-xs mt-2">{algo.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Features Grid */}
      <div>
        <h2 className="section-title mb-8 justify-center text-2xl">
          <span>✨</span> Platform Features
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map(feature => (
            <div key={feature.title} className="card-hover group">
              <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${feature.color} flex items-center justify-center text-2xl mb-4 shadow-lg`}>
                {feature.icon}
              </div>
              <h3 className="font-semibold text-slate-100 mb-2 text-lg">{feature.title}</h3>
              <p className="text-slate-400 text-sm leading-relaxed">{feature.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Quick start */}
      <div className="card border-primary-500/30 bg-gradient-to-br from-dark-800 to-dark-900">
        <h2 className="section-title mb-6">🚀 Quick Start</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[
            { step: '01', title: 'Choose Input', desc: 'Type text or drop a file (up to 10 MB). Images, PDFs, videos all supported.' },
            { step: '02', title: 'Configure Keys', desc: 'Enter hex key and nonce. Platform auto-validates lengths per algorithm.' },
            { step: '03', title: 'Encrypt & Analyze', desc: 'See ciphertext, internal state, performance metrics, and download results.' },
          ].map(item => (
            <div key={item.step} className="flex gap-4">
              <div className="text-4xl font-bold text-primary-500/30 font-mono shrink-0">{item.step}</div>
              <div>
                <div className="font-semibold text-slate-200 mb-1">{item.title}</div>
                <p className="text-slate-400 text-sm">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
