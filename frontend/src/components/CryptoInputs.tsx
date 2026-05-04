import { useState } from 'react';
import clsx from 'clsx';

export interface CryptoParams {
  key: string;
  nonce: string;
  aad?: string;
}

interface CryptoInputsProps {
  params: CryptoParams;
  onChange: (params: CryptoParams) => void;
  algorithms: string[];
  showAad?: boolean;
}

// Key requirements per algorithm (bytes)
const KEY_REQUIREMENTS: Record<string, { keyBytes: number; nonceBytes: number }> = {
  trivium:      { keyBytes: 10, nonceBytes: 10 },
  grain128aead: { keyBytes: 16, nonceBytes: 12 },
  mickey:       { keyBytes: 10, nonceBytes: 10 },
  chacha20:     { keyBytes: 32, nonceBytes: 12 },
  ascon:        { keyBytes: 16, nonceBytes: 16 },
};

function generateHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function validateHex(hex: string, expectedBytes?: number): { valid: boolean; message?: string } {
  const clean = hex.replace(/\s/g, '');
  if (!/^[0-9a-fA-F]*$/.test(clean)) return { valid: false, message: "Hex noto'g'ri" };
  if (clean.length % 2 !== 0) return { valid: false, message: "Hex uzunligi noto'g'ri" };
  if (expectedBytes && clean.length / 2 !== expectedBytes) {
    return { valid: false, message: `Kutilgan ${expectedBytes} bayt (${expectedBytes * 2} hex belgisi), olingan ${clean.length / 2}` };
  }
  return { valid: true };
}

export default function CryptoInputs({ params, onChange, algorithms, showAad = true }: CryptoInputsProps) {
  const [showAadField, setShowAadField] = useState(false);

  const hasAEAD = algorithms.some(a => ['grain128aead', 'ascon'].includes(a)) ||
                  algorithms.length === 0; // all selected

  // Determine validation: use strictest key requirement if multiple algorithms
  const getKeyHint = () => {
    if (algorithms.length === 1) {
      const req = KEY_REQUIREMENTS[algorithms[0]];
      return req ? `${req.keyBytes * 8}-bit (${req.keyBytes * 2} hex belgisi)` : '';
    }
    if (algorithms.length === 0) return "Algoritmga qarab avtomatik to'ldiriladi yoki kesiladi";
    return "Algoritmga qarab avtomatik to'ldiriladi yoki kesiladi";
  };

  const keyValidation = algorithms.length === 1
    ? validateHex(params.key, KEY_REQUIREMENTS[algorithms[0]]?.keyBytes)
    : validateHex(params.key);

  const nonceValidation = algorithms.length === 1
    ? validateHex(params.nonce, KEY_REQUIREMENTS[algorithms[0]]?.nonceBytes)
    : validateHex(params.nonce);

  const autoFill = () => {
    // Use chacha20 defaults for multi-algo (longest common key)
    const keyBytes = algorithms.length === 1 ? (KEY_REQUIREMENTS[algorithms[0]]?.keyBytes ?? 32) : 32;
    const nonceBytes = algorithms.length === 1 ? (KEY_REQUIREMENTS[algorithms[0]]?.nonceBytes ?? 12) : 12;
    onChange({
      key: generateHex(keyBytes),
      nonce: generateHex(nonceBytes),
      aad: params.aad,
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-slate-300 font-medium text-sm">Kriptografik parametrlar</h3>
        <button onClick={autoFill} className="text-xs btn-ghost py-1">
          🎲 Avto to'ldirish
        </button>
      </div>

      {/* Key */}
      <div>
        <label className="label">
          Kalit (Hex)
          <span className="text-slate-500 font-normal ml-2 text-xs">{getKeyHint()}</span>
        </label>
        <div className="relative">
          <input
            type="text"
            value={params.key}
            onChange={e => onChange({ ...params, key: e.target.value })}
            className={clsx(
              'input-field pr-20',
              params.key && !keyValidation.valid ? 'border-red-500/60 focus:ring-red-500' : ''
            )}
            placeholder="Hex formatdagi kalitni kiriting (masalan 0102030405060708090a...)"
            spellCheck={false}
          />
          <button
            onClick={() => {
              const bytes = algorithms.length === 1 ? (KEY_REQUIREMENTS[algorithms[0]]?.keyBytes ?? 32) : 32;
              onChange({ ...params, key: generateHex(bytes) });
            }}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-primary-400 hover:text-primary-300 px-2 py-1 rounded"
          >
            Tasodifiy
          </button>
        </div>
        {params.key && !keyValidation.valid && (
          <p className="text-red-400 text-xs mt-1">⚠ {keyValidation.message}</p>
        )}
      </div>

      {/* Nonce / IV */}
      <div>
        <label className="label">
          Nonce / IV (Hex)
          <span className="text-slate-500 font-normal ml-2 text-xs">
            {algorithms.length === 1 && KEY_REQUIREMENTS[algorithms[0]]
              ? `${KEY_REQUIREMENTS[algorithms[0]].nonceBytes * 8}-bit`
              : "Algoritmga bog'liq"}
          </span>
        </label>
        <div className="relative">
          <input
            type="text"
            value={params.nonce}
            onChange={e => onChange({ ...params, nonce: e.target.value })}
            className={clsx(
              'input-field pr-20',
              params.nonce && !nonceValidation.valid ? 'border-red-500/60 focus:ring-red-500' : ''
            )}
            placeholder="Hex formatdagi nonce/IV kiriting"
            spellCheck={false}
          />
          <button
            onClick={() => {
              const bytes = algorithms.length === 1 ? (KEY_REQUIREMENTS[algorithms[0]]?.nonceBytes ?? 12) : 12;
              onChange({ ...params, nonce: generateHex(bytes) });
            }}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-primary-400 hover:text-primary-300 px-2 py-1 rounded"
          >
            Tasodifiy
          </button>
        </div>
        {params.nonce && !nonceValidation.valid && (
          <p className="text-red-400 text-xs mt-1">⚠ {nonceValidation.message}</p>
        )}
      </div>

      {/* AAD (for AEAD) */}
      {showAad && hasAEAD && (
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="label mb-0">
              Qo'shimcha autentifikatsiya ma'lumotlari (AAD)
              <span className="badge-purple ml-2">AEAD</span>
            </label>
            <button
              onClick={() => setShowAadField(!showAadField)}
              className="text-xs text-slate-500 hover:text-slate-300"
            >
              {showAadField ? 'Yashirish' : "Ko'rsatish"}
            </button>
          </div>
          {showAadField && (
            <input
              type="text"
              value={params.aad ?? ''}
              onChange={e => onChange({ ...params, aad: e.target.value })}
              className="input-field"
              placeholder="Grain-128AEAD va Ascon uchun ixtiyoriy hex-AAD"
              spellCheck={false}
            />
          )}
        </div>
      )}

      {/* Key hint table */}
      <details className="group">
        <summary className="text-xs text-slate-500 hover:text-slate-400 cursor-pointer select-none">
          📋 Kalit/Nonce o'lchamlari
        </summary>
        <div className="mt-2 overflow-x-auto">
          <table className="w-full text-xs text-slate-400 border-separate border-spacing-0">
            <thead>
              <tr>
                {['Algoritm', 'Kalit', 'Nonce', 'Turi'].map(h => (
                  <th key={h} className="text-left py-1.5 px-2 bg-dark-950/50 border-b border-slate-700/50 font-medium text-slate-300">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                  ['Trivium', '80-bit (20 hex)', '80-bit (20 hex)', "Oqim"],
                  ['Grain-128AEAD', '128-bit (32 hex)', '96-bit (24 hex)', 'AEAD'],
                  ['MICKEY-v2', '80-bit (20 hex)', '80-bit (20 hex)', "Oqim"],
                  ['ChaCha20', '256-bit (64 hex)', '96-bit (24 hex)', "Oqim"],
                  ['Ascon-AEAD128', '128-bit (32 hex)', '128-bit (32 hex)', 'AEAD'],
              ].map(([name, key, nonce, type]) => (
                <tr key={name} className="border-b border-slate-800/50">
                  <td className="py-1.5 px-2 font-medium text-slate-300">{name}</td>
                  <td className="py-1.5 px-2 font-mono">{key}</td>
                  <td className="py-1.5 px-2 font-mono">{nonce}</td>
                  <td className="py-1.5 px-2">
                    <span className={type === 'AEAD' ? 'badge-purple' : 'badge-blue'}>{type}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
