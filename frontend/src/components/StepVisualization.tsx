import { useState } from 'react';
import clsx from 'clsx';

interface StepVisualizationProps {
  steps: unknown[];
  algorithm: string;
}

function formatValue(v: unknown): string {
  if (typeof v === 'number') return `0x${v.toString(16).padStart(8, '0')}`;
  if (typeof v === 'bigint') return `0x${v.toString(16).padStart(16, '0')}`;
  if (Array.isArray(v)) {
    if (v.length <= 8) return `[${v.join(', ')}]`;
    return `[${v.slice(0, 8).join(', ')}... +${v.length - 8}]`;
  }
  return String(v);
}

function TriviumStep({ step }: { step: Record<string, unknown> }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
      <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
        <div className="text-blue-300 font-semibold mb-2">Register A (bits 0-31)</div>
        <div className="text-slate-300">{formatValue(step.regA)}</div>
        <div className="text-slate-500 mt-1">t1 = {String(step.t1)}</div>
      </div>
      <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-3">
        <div className="text-emerald-300 font-semibold mb-2">Register B (bits 0-31)</div>
        <div className="text-slate-300">{formatValue(step.regB)}</div>
        <div className="text-slate-500 mt-1">t2 = {String(step.t2)}</div>
      </div>
      <div className="bg-violet-500/10 border border-violet-500/30 rounded-lg p-3">
        <div className="text-violet-300 font-semibold mb-2">Register C (bits 0-31)</div>
        <div className="text-slate-300">{formatValue(step.regC)}</div>
        <div className="text-slate-500 mt-1">t3 = {String(step.t3)}</div>
      </div>
      <div className="md:col-span-3 bg-dark-800/50 rounded-lg px-3 py-2 flex gap-6">
        <span>Step: <span className="text-primary-300">{String(step.step)}</span></span>
        <span>Output bit: <span className="text-amber-300 font-bold">{String(step.bit)}</span></span>
      </div>
    </div>
  );
}

function GrainStep({ step }: { step: Record<string, unknown> }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
      <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-3">
        <div className="text-emerald-300 font-semibold mb-2">LFSR (bits 0-7)</div>
        <div className="flex gap-1">
          {(step.lfsrSlice as number[])?.map((b, i) => (
            <span key={i} className={clsx(
              'w-6 h-6 rounded flex items-center justify-center text-xs',
              b ? 'bg-emerald-500/40 text-emerald-200' : 'bg-slate-700 text-slate-400'
            )}>{b}</span>
          ))}
        </div>
      </div>
      <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
        <div className="text-amber-300 font-semibold mb-2">NFSR (bits 0-7)</div>
        <div className="flex gap-1">
          {(step.nfsrSlice as number[])?.map((b, i) => (
            <span key={i} className={clsx(
              'w-6 h-6 rounded flex items-center justify-center text-xs',
              b ? 'bg-amber-500/40 text-amber-200' : 'bg-slate-700 text-slate-400'
            )}>{b}</span>
          ))}
        </div>
      </div>
      <div className="md:col-span-2 bg-dark-800/50 rounded-lg px-3 py-2 flex gap-6">
        <span>Step: <span className="text-primary-300">{String(step.step)}</span></span>
        <span>Keystream bit: <span className="text-amber-300 font-bold">{String(step.keystreamBit)}</span></span>
      </div>
    </div>
  );
}

function MickeyStep({ step }: { step: Record<string, unknown> }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
      <div className="bg-violet-500/10 border border-violet-500/30 rounded-lg p-3">
        <div className="text-violet-300 font-semibold mb-2">R Register (bits 0-7)</div>
        <div className="flex gap-1">
          {(step.rSlice as number[])?.map((b, i) => (
            <span key={i} className={clsx(
              'w-6 h-6 rounded flex items-center justify-center text-xs',
              b ? 'bg-violet-500/40 text-violet-200' : 'bg-slate-700 text-slate-400'
            )}>{b}</span>
          ))}
        </div>
        <div className="text-slate-500 mt-2">Control bit: {String(step.controlBitR)}</div>
      </div>
      <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-3">
        <div className="text-rose-300 font-semibold mb-2">S Register (bits 0-7)</div>
        <div className="flex gap-1">
          {(step.sSlice as number[])?.map((b, i) => (
            <span key={i} className={clsx(
              'w-6 h-6 rounded flex items-center justify-center text-xs',
              b ? 'bg-rose-500/40 text-rose-200' : 'bg-slate-700 text-slate-400'
            )}>{b}</span>
          ))}
        </div>
        <div className="text-slate-500 mt-2">Control bit: {String(step.controlBitS)}</div>
      </div>
      <div className="md:col-span-2 bg-dark-800/50 rounded-lg px-3 py-2 flex gap-6">
        <span>Step: <span className="text-primary-300">{String(step.step)}</span></span>
        <span>Output bit: <span className="text-amber-300 font-bold">{String(step.outputBit)}</span></span>
      </div>
    </div>
  );
}

function ChaCha20Step({ step }: { step: Record<string, unknown> }) {
  const rounds = step.rounds as Array<Record<string, unknown>>;
  const initial = step.initialState as number[];
  const final = step.finalState as number[];

  return (
    <div className="space-y-3 font-mono text-xs">
      {/* Initial state matrix */}
      <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
        <div className="text-amber-300 font-semibold mb-2">Initial State Matrix (Block {String(step.blockIndex)})</div>
        <div className="grid grid-cols-4 gap-1">
          {initial?.slice(0, 16).map((v, i) => (
            <div key={i} className="bg-dark-800/60 rounded px-2 py-1 text-slate-300 overflow-hidden text-center">
              {`0x${v.toString(16).padStart(8, '0')}`}
            </div>
          ))}
        </div>
      </div>

      {/* Sample quarter rounds */}
      {rounds && rounds.length > 0 && (
        <div className="bg-dark-800/50 rounded-lg p-3">
          <div className="text-slate-300 font-semibold mb-2">Quarter Round (Round 0, QR 0)</div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {(['a', 'b', 'c', 'd'] as const).map(k => (
              <div key={k} className="text-center">
                <div className="text-slate-500 mb-1">{k.toUpperCase()}</div>
                <div className="text-primary-300">{`0x${(rounds[0][k] as number)?.toString(16).padStart(8, '0') ?? '?'}`}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Final state */}
      <div className="bg-primary-500/10 border border-primary-500/30 rounded-lg p-3">
        <div className="text-primary-300 font-semibold mb-2">Output State (after add-back)</div>
        <div className="grid grid-cols-4 gap-1">
          {final?.slice(0, 16).map((v, i) => (
            <div key={i} className="bg-dark-800/60 rounded px-2 py-1 text-slate-300 overflow-hidden text-center">
              {`0x${v.toString(16).padStart(8, '0')}`}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AsconStep({ step }: { step: Record<string, unknown> }) {
  const before = step.stateBefore as unknown[];
  const after = step.stateAfter as unknown[];

  return (
    <div className="space-y-3 font-mono text-xs">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="bg-dark-800/50 rounded-lg p-3">
          <div className="text-slate-400 font-semibold mb-2">State Before ({String(step.phase)})</div>
          {before?.map((v, i) => (
            <div key={i} className="flex gap-2 mb-1">
              <span className="text-slate-600 w-4">x{i}</span>
              <span className="text-slate-300">{formatValue(v)}</span>
            </div>
          ))}
        </div>
        <div className="bg-primary-500/10 border border-primary-500/30 rounded-lg p-3">
          <div className="text-primary-300 font-semibold mb-2">State After</div>
          {after?.map((v, i) => (
            <div key={i} className="flex gap-2 mb-1">
              <span className="text-slate-600 w-4">x{i}</span>
              <span className="text-slate-300">{formatValue(v)}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="bg-dark-800/50 rounded-lg px-3 py-2">
        <span>Block: <span className="text-primary-300">{String(step.blockIndex)}</span></span>
        <span className="ml-4">Phase: <span className="text-amber-300">{String(step.phase)}</span></span>
      </div>
    </div>
  );
}

export default function StepVisualization({ steps, algorithm }: StepVisualizationProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const step = steps[currentStep] as Record<string, unknown>;

  const renderStep = () => {
    switch (algorithm) {
      case 'trivium': return <TriviumStep step={step} />;
      case 'grain128aead': return <GrainStep step={step} />;
      case 'mickey': return <MickeyStep step={step} />;
      case 'chacha20': return <ChaCha20Step step={step} />;
      case 'ascon': return <AsconStep step={step} />;
      default: return <pre className="text-xs text-slate-400">{JSON.stringify(step, null, 2)}</pre>;
    }
  };

  return (
    <div className="mt-3 bg-dark-950/60 border border-slate-700/40 rounded-xl p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h4 className="text-slate-300 font-medium text-sm flex items-center gap-2">
          🔬 Internal State — Step {currentStep + 1} / {steps.length}
        </h4>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
            disabled={currentStep === 0}
            className="btn-ghost px-2 py-1 text-sm disabled:opacity-30"
          >
            ←
          </button>
          <span className="text-slate-500 text-xs font-mono">{currentStep + 1}/{steps.length}</span>
          <button
            onClick={() => setCurrentStep(Math.min(steps.length - 1, currentStep + 1))}
            disabled={currentStep === steps.length - 1}
            className="btn-ghost px-2 py-1 text-sm disabled:opacity-30"
          >
            →
          </button>
        </div>
      </div>

      {/* Step slider */}
      <input
        type="range"
        min={0}
        max={steps.length - 1}
        value={currentStep}
        onChange={e => setCurrentStep(parseInt(e.target.value))}
        className="w-full accent-primary-500"
      />

      {/* Step content */}
      {renderStep()}
    </div>
  );
}
