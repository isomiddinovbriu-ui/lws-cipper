import { Link } from 'react-router-dom';

const features = [
  {
    icon: '🔒',
    title: "Ko'p algoritm bilan shifrlash",
    desc: "Matn va fayllarni 5 ta yengil shifrdan bir yoki bir nechta yordamida shifrlang. Natijalarni yonma-yon taqqoslang.",
    color: 'from-primary-500 to-primary-700',
  },
  {
    icon: '🔓',
    title: "Deshifrlash va tekshirish",
    desc: "Grain-128AEAD va Ascon uchun AEAD autentifikatsiya tegini tekshirish bilan deshifrlash.",
    color: 'from-emerald-500 to-emerald-700',
  },
  {
    icon: '📊',
    title: "Ishlash sinovlari",
    desc: "O'tkazuvchanlik, kechikish va xotira sarfini o'lchang. Vizual grafiklar va radar taqqoslash.",
    color: 'from-accent-500 to-accent-700',
  },
  {
    icon: '🔬',
    title: "Bosqichma-bosqich vizualizatsiya",
    desc: "Ichki holat o'zgarishlarini ko'ring: shift registrlar, quarter-round, permutatsiya bosqichlari.",
    color: 'from-amber-500 to-amber-700',
  },
  {
    icon: '💾',
    title: "Eksport qilish",
    desc: "Natijalarni TXT, JSON, CSV sifatida yuklab oling. Shifrlangan fayllarni .enc sifatida saqlang.",
    color: 'from-rose-500 to-rose-700',
  },
  {
    icon: '🔐',
    title: "AEAD autentifikatsiya",
    desc: "Grain-128AEAD va Ascon-AEAD128 uchun AAD bilan to'liq autentifikatsiyalangan shifrlash.",
    color: 'from-indigo-500 to-indigo-700',
  },
];

const algorithms = [
  { name: 'Trivium', badge: 'eSTREAM', color: 'badge-blue', desc: "80-bit kalit · 288-bit holat" },
  { name: 'Grain-128AEAD', badge: 'NIST LWC', color: 'badge-green', desc: "128-bit kalit · LFSR+NFSR" },
  { name: 'MICKEY-v2', badge: 'eSTREAM', color: 'badge-blue', desc: "80-bit kalit · Noqonuniy soatlash" },
  { name: 'ChaCha20', badge: 'RFC 7539', color: 'badge-amber', desc: '256-bit kalit · ARX dizayni' },
  { name: 'Ascon-AEAD128', badge: 'NIST Standard', color: 'badge-purple', desc: '128-bit kalit · Sponge AEAD' },
];

export default function HomePage() {
  return (
    <div className="space-y-16">
      {/* Hero */}
      <div className="text-center py-12">
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary-500/10 border border-primary-500/30 text-primary-300 text-sm font-medium mb-8">
          <span className="w-2 h-2 rounded-full bg-primary-400 animate-pulse-slow"></span>
          Ishlab chiqarishga tayyor kriptografik tahlil platformasi
        </div>

        <h1 className="text-5xl md:text-6xl font-bold mb-6 leading-tight">
          <span className="text-gradient">Yengil vaznli shifrlash algoritmlar</span>
          <br />
            <span className="text-slate-600 dark:text-slate-100">
              Tahlil to'plami
            </span>
        </h1>

        <p className="text-xl text-slate-400 max-w-2xl mx-auto mb-10 leading-relaxed">
          5 ta NIST/eSTREAM yengil kriptografik algoritmlarni shifrlash, deshifrlash va ish faoliyatini sinovdan o'tkazing.
          Ichki holatni vizualizatsiya qiling va ishlash metrikalarini real vaqtda taqqoslang.
        </p>

<div className="flex flex-wrap justify-center items-center gap-6 mt-4">
  {/* 1. Shifrlash Tugmasi - Asosiy harakat (Primary Glow) */}
  <Link 
    to="/encrypt" 
    className="group relative inline-flex items-center justify-center px-8 py-4 font-bold text-white transition-all duration-300 bg-blue-600 rounded-2xl hover:bg-blue-500 hover:scale-105 hover:shadow-[0_0_25px_rgba(37,99,235,0.5)] active:scale-95"
  >
    <span className="flex items-center gap-2">
      <span className="text-xl group-hover:rotate-12 transition-transform">🔒</span>
      Shifrlashni boshlash
    </span>
  </Link>

  {/* 2. Sinovlar Tugmasi - Glassmorphism (Secondary) */}
  <Link 
    to="/benchmark" 
    className="group inline-flex items-center justify-center px-8 py-4 font-bold text-slate-700 dark:text-slate-200 transition-all duration-300 bg-slate-100 dark:bg-slate-800/50 backdrop-blur-md border border-slate-200 dark:border-slate-700 rounded-2xl hover:bg-white dark:hover:bg-slate-800 hover:border-blue-400 dark:hover:border-blue-500 hover:scale-105 active:scale-95 shadow-sm"
  >
    <span className="flex items-center gap-2">
      <span className="text-xl group-hover:animate-bounce">📊</span>
      Sinovlarni ishga tushur
    </span>
  </Link>

  {/* 3. Algoritmlar Tugmasi - Emerald Minimalist */}
  <Link 
    to="/algorithms" 
    className="group relative inline-flex items-center justify-center px-8 py-4 font-bold text-emerald-600 dark:text-emerald-400 transition-all duration-300 border-2 border-emerald-500/20 dark:border-emerald-500/30 rounded-2xl hover:bg-emerald-500 hover:text-white dark:hover:bg-emerald-500/20 hover:scale-105 active:scale-95 overflow-hidden"
  >
    <span className="absolute inset-0 w-full h-full bg-emerald-500 transition-all duration-300 origin-bottom scale-y-0 group-hover:scale-y-100 -z-10"></span>
    <span className="flex items-center gap-2">
      <span className="text-xl group-hover:rotate-12 transition-transform">🧬</span>
      Algoritmlar
      <span className="inline-block transition-transform duration-300 group-hover:translate-x-2">→</span>
    </span>
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
        <h2 className="section-title mb-8 justify-center text-2xl text-slate-800 dark:text-slate-100 flex items-center gap-2">
          <span>✨</span> Platforma xususiyatlari
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
        <h2 className="section-title mb-6">🚀 Tez boshlash</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[
            { step: '01', title: "Kirishni tanlang", desc: "Matn kiriting yoki faylni tashlang (10 MB gacha). Rasmlar, PDF, video qo'llab-quvvatlanadi." },
            { step: '02', title: "Kalitlarni sozlash", desc: "Hex formatdagi kalit va nonce kiriting. Platforma algoritm bo'yicha uzunlikni avtomatik tekshiradi." },
            { step: '03', title: "Shifrlash va tahlil qilish", desc: "Shifrlangan matn, ichki holat, ishlash metrikalarini ko'ring va natijalarni yuklab oling." },
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
