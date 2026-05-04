import clsx from 'clsx';

interface AlgorithmSelectorProps {
  selected: string[];
  onChange: (selected: string[]) => void;
}

const ALGORITHMS = [
  { id: 'trivium', name: 'Trivium', badge: 'eSTREAM', keyBits: 80, nonceBits: 80, isAEAD: false },
  { id: 'grain128aead', name: 'Grain-128AEAD', badge: 'NIST LWC', keyBits: 128, nonceBits: 96, isAEAD: true },
  { id: 'mickey', name: 'MICKEY-v2', badge: 'eSTREAM', keyBits: 80, nonceBits: 80, isAEAD: false },
  { id: 'chacha20', name: 'ChaCha20', badge: 'RFC 7539', keyBits: 256, nonceBits: 96, isAEAD: false },
  { id: 'ascon', name: 'Ascon-AEAD128', badge: 'NIST Std', keyBits: 128, nonceBits: 128, isAEAD: true },
];

export default function AlgorithmSelector({ selected, onChange }: AlgorithmSelectorProps) {
  const toggle = (id: string) => {
    if (selected.includes(id)) {
      onChange(selected.filter(s => s !== id));
    } else {
      onChange([...selected, id]);
    }
  };

  const selectAll = () => onChange(ALGORITHMS.map(a => a.id));
  const clearAll = () => onChange([]);

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <label className="label mb-0">Algorithms</label>
        <div className="flex gap-2">
          <button onClick={selectAll} className="text-xs text-primary-400 hover:text-primary-300 transition-colors">
            All
          </button>
          <span className="text-slate-600">·</span>
          <button onClick={clearAll} className="text-xs text-slate-500 hover:text-slate-400 transition-colors">
            None
          </button>
          {selected.length === 0 && (
            <span className="text-xs text-amber-400 ml-2">→ will run ALL</span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2">
        {ALGORITHMS.map(algo => {
          const isSelected = selected.includes(algo.id);
          return (
            <button
              key={algo.id}
              onClick={() => toggle(algo.id)}
              className={clsx(
                'relative flex flex-col items-start p-3 rounded-xl border text-left transition-all duration-200',
                isSelected
                  ? 'border-primary-500 bg-primary-500/10 shadow-lg shadow-primary-500/10'
                  : 'border-slate-700/50 bg-dark-900/40 hover:border-slate-600'
              )}
            >
              {/* Checkmark */}
              <div className={clsx(
                'absolute top-2 right-2 w-5 h-5 rounded-full border flex items-center justify-center transition-all',
                isSelected ? 'bg-primary-500 border-primary-500' : 'border-slate-600'
              )}>
                {isSelected && <span className="text-white text-xs">✓</span>}
              </div>

              <span className="font-semibold text-sm text-slate-200 pr-6">{algo.name}</span>
              <span className={clsx(
                'text-xs mt-1 px-1.5 py-0.5 rounded',
                algo.isAEAD ? 'bg-accent-500/20 text-accent-300' : 'bg-primary-500/20 text-primary-300'
              )}>
                {algo.badge}
              </span>
              <div className="mt-2 text-xs text-slate-500">
                Key: {algo.keyBits}b · IV: {algo.nonceBits}b
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export { ALGORITHMS };
