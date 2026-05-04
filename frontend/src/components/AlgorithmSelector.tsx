import clsx from 'clsx';

interface AlgorithmSelectorProps {
  selected: string[];
  onChange: (selected: string[]) => void;
}

const ALGORITHMS = [
  { id: 'trivium', name: 'Trivium', isAEAD: false },
  { id: 'grain128aead', name: 'Grain-128AEAD', isAEAD: true },
  { id: 'mickey', name: 'MICKEY-v2', isAEAD: false },
  { id: 'chacha20', name: 'ChaCha20', isAEAD: false },
  { id: 'ascon', name: 'Ascon-AEAD128', isAEAD: true },
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
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <label className="label mb-0">Algoritmlar</label>
        <div className="flex gap-2 text-xs">

          <button onClick={clearAll} className="text-slate-500 hover:text-slate-400">
            Tozalash
          </button>
        </div>
      </div>

      {/* Chips */}
      <div className="flex flex-wrap gap-2">
        {ALGORITHMS.map(algo => {
          const isSelected = selected.includes(algo.id);

          return (
            <button
              key={algo.id}
              onClick={() => toggle(algo.id)}
              className={clsx(
                "px-3 py-1.5 rounded-full text-xs font-medium border transition-all",
                isSelected
                  ? "bg-primary-600 text-white border-primary-600 shadow"
                  : "bg-dark-900 text-slate-400 border-slate-700 hover:border-slate-500 hover:text-slate-200"
              )}
            >
              {algo.name}
              {algo.isAEAD && (
                <span className="ml-1 text-[10px] opacity-70">AEAD</span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}

