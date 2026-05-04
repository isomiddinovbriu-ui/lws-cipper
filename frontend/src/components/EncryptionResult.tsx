import { useState } from 'react';
import type { EncryptResult } from '../services/api';
import { downloadReport, downloadEncryptedFile, exportJson } from '../services/api';
import StepVisualization from './StepVisualization';
import toast from 'react-hot-toast';
import clsx from 'clsx';

interface Props {
  result: EncryptResult;
  index: number;
}

const ALGO_COLORS: Record<string, string> = {
  trivium: 'from-blue-500 to-blue-700',
  grain128aead: 'from-emerald-500 to-emerald-700',
  mickey: 'from-violet-500 to-violet-700',
  chacha20: 'from-amber-500 to-amber-700',
  ascon: 'from-rose-500 to-rose-700',
};

function copyToClipboard(text: string, label: string) {
  navigator.clipboard.writeText(text).then(() => toast.success(`${label} copied!`));
}

export default function EncryptionResult({ result, index }: Props) {
  const [expanded, setExpanded] = useState(index === 0);
  const [showSteps, setShowSteps] = useState(false);

  const color = ALGO_COLORS[result.algorithm] ?? 'from-slate-500 to-slate-700';
  const preview = result.ciphertext.slice(0, 64) + (result.ciphertext.length > 64 ? '...' : '');

  return (
    <div className={clsx(
      'border rounded-xl overflow-hidden transition-all duration-300',
      expanded ? 'border-slate-600' : 'border-slate-700/50'
    )}>
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-4 bg-dark-800/80 hover:bg-dark-800 transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full bg-gradient-to-br ${color}`}></div>
          <span className="font-semibold text-slate-200 capitalize">{result.algorithm}</span>
          {result.tag && <span className="badge-green text-xs">AEAD ✓</span>}
          <span className="text-slate-500 text-xs font-mono">{preview}</span>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right hidden sm:block">
            <div className="text-primary-300 text-sm font-mono">{result.timeTaken.toFixed(2)} ms</div>
            <div className="text-slate-500 text-xs">{result.throughput.toFixed(3)} MB/s</div>
          </div>
          <span className="text-slate-500 text-lg">{expanded ? '▲' : '▼'}</span>
        </div>
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="p-5 space-y-5 bg-dark-900/50 animate-slide-in">
          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Time', value: `${result.timeTaken.toFixed(3)} ms`, icon: '⏱' },
              { label: 'Throughput', value: `${result.throughput.toFixed(3)} MB/s`, icon: '🚀' },
              { label: 'Ciphertext', value: `${result.ciphertext.length / 2} bytes`, icon: '📦' },
              { label: 'Auth Tag', value: result.tag ? '✅ Present' : '—', icon: '🔐' },
            ].map(stat => (
              <div key={stat.label} className="bg-dark-800/60 border border-slate-700/30 rounded-lg p-3 text-center">
                <div className="text-lg mb-1">{stat.icon}</div>
                <div className="text-slate-200 font-semibold text-sm">{stat.value}</div>
                <div className="text-slate-500 text-xs">{stat.label}</div>
              </div>
            ))}
          </div>

          {/* Ciphertext */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="label mb-0">Ciphertext (Hex)</label>
              <button onClick={() => copyToClipboard(result.ciphertext, 'Ciphertext')} className="btn-ghost text-xs py-1">
                📋 Copy
              </button>
            </div>
            <div className="hex-display max-h-32 overflow-y-auto">{result.ciphertext}</div>
          </div>

          {/* Auth Tag */}
          {result.tag && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="label mb-0">Authentication Tag</label>
                <button onClick={() => copyToClipboard(result.tag!, 'Tag')} className="btn-ghost text-xs py-1">
                  📋 Copy
                </button>
              </div>
              <div className="hex-display">{result.tag}</div>
            </div>
          )}

          {/* Keystream (truncated for display) */}
          {result.keystream && (
            <div>
              <label className="label">Keystream (first 64 bytes hex)</label>
              <div className="hex-display">{result.keystream.slice(0, 128)}</div>
            </div>
          )}

          {/* Step Visualization */}
          {result.steps && result.steps.length > 0 && (
            <div>
              <button
                onClick={() => setShowSteps(!showSteps)}
                className="btn-ghost text-sm w-full justify-center border border-slate-700/50"
              >
                {showSteps ? '▲ Hide' : '▼ Show'} Step-by-Step Internal State ({result.steps.length} steps captured)
              </button>
              {showSteps && <StepVisualization steps={result.steps} algorithm={result.algorithm} />}
            </div>
          )}

          {/* Actions */}
          <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-700/30">
            <button
              onClick={() => downloadReport(result.txtReport, `${result.algorithm}_result`)}
              className="btn-secondary text-sm"
            >
              📄 Download TXT
            </button>
            <button
              onClick={() => downloadEncryptedFile(result.ciphertext, `${result.algorithm}_encrypted`)}
              className="btn-secondary text-sm"
            >
              💾 Download .enc
            </button>
            <button
              onClick={() => exportJson(result, `${result.algorithm}_result`)}
              className="btn-secondary text-sm"
            >
              📦 Export JSON
            </button>
            <button
              onClick={() => copyToClipboard(result.txtReport, 'Report')}
              className="btn-ghost text-sm"
            >
              📋 Copy Report
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
