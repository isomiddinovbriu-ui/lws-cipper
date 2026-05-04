import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import toast from 'react-hot-toast';
import clsx from 'clsx';
import AlgorithmSelector from '../components/AlgorithmSelector';
import CryptoInputs, { CryptoParams } from '../components/CryptoInputs';
import EncryptionResult from '../components/EncryptionResult';
import { encryptText, encryptFile, EncryptResult } from '../services/api';

type InputMode = 'text' | 'file';

const DEFAULT_PARAMS: CryptoParams = {
  key: '',
  nonce: '',
  aad: '',
};

export default function EncryptPage() {
  const [inputMode, setInputMode] = useState<InputMode>('text');
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [algorithms, setAlgorithms] = useState<string[]>([]);
  const [params, setParams] = useState<CryptoParams>(DEFAULT_PARAMS);
  const [captureSteps, setCaptureSteps] = useState(true);
  const [results, setResults] = useState<EncryptResult[]>([]);
  const [loading, setLoading] = useState(false);

  const onDrop = useCallback((accepted: File[]) => {
    if (accepted[0]) {
      setFile(accepted[0]);
      toast.success(`File loaded: ${accepted[0].name} (${(accepted[0].size / 1024).toFixed(1)} KB)`);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    maxSize: 10 * 1024 * 1024,
    multiple: false,
    onDropRejected: ([rejection]) => {
      toast.error(rejection.errors[0]?.message ?? 'File rejected');
    },
  });

  const handleEncrypt = async () => {
    if (!params.key || !params.nonce) {
      toast.error('Please provide key and nonce');
      return;
    }

    if (inputMode === 'text' && !text.trim()) {
      toast.error('Please enter text to encrypt');
      return;
    }
    if (inputMode === 'file' && !file) {
      toast.error('Please select a file to encrypt');
      return;
    }

    setLoading(true);
    setResults([]);

    try {
      if (inputMode === 'text') {
        const res = await encryptText({
          text,
          algorithms: algorithms.length > 0 ? algorithms : undefined,
          key: params.key,
          nonce: params.nonce,
          aad: params.aad || undefined,
          captureSteps,
        });
        setResults(res.data);
        toast.success(`Encrypted with ${res.data.length} algorithm(s)`);
      } else if (file) {
        // For file: use single algorithm or default to chacha20
        const algo = algorithms.length === 1 ? algorithms[0] : 'chacha20';
        const formData = new FormData();
        formData.append('file', file);
        formData.append('algorithm', algo);
        formData.append('key', params.key);
        formData.append('nonce', params.nonce);
        if (params.aad) formData.append('aad', params.aad);
        formData.append('captureSteps', String(captureSteps));
        const res = await encryptFile(formData);
        setResults([res.data]);
        toast.success(`File encrypted: ${res.data.originalFilename}`);
      }
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-slate-100 mb-2">🔒 Encrypt</h1>
        <p className="text-slate-400">Encrypt text or files using one or multiple lightweight ciphers</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
        {/* Left: Configuration */}
        <div className="xl:col-span-1 space-y-6">
          {/* Input Mode */}
          <div className="card">
            <h2 className="section-title mb-4 text-base">📥 Input</h2>
            <div className="flex gap-2 mb-4">
              {(['text', 'file'] as const).map(mode => (
                <button
                  key={mode}
                  onClick={() => setInputMode(mode)}
                  className={inputMode === mode ? 'tab-active' : 'tab-inactive'}
                >
                  {mode === 'text' ? '📝 Text' : '📁 File'}
                </button>
              ))}
            </div>

            {inputMode === 'text' ? (
              <textarea
                value={text}
                onChange={e => setText(e.target.value)}
                className="input-field min-h-[140px] resize-y"
                placeholder="Enter plaintext to encrypt..."
              />
            ) : (
              <div
                {...getRootProps()}
                className={clsx(
                  'border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-200',
                  isDragActive
                    ? 'border-primary-400 bg-primary-500/10'
                    : 'border-slate-700 hover:border-slate-500'
                )}
              >
                <input {...getInputProps()} />
                {file ? (
                  <div>
                    <div className="text-4xl mb-2">📄</div>
                    <div className="text-slate-200 font-medium">{file.name}</div>
                    <div className="text-slate-500 text-sm mt-1">{(file.size / 1024).toFixed(1)} KB</div>
                    <button
                      onClick={e => { e.stopPropagation(); setFile(null); }}
                      className="text-red-400 text-xs mt-2 hover:text-red-300"
                    >
                      Remove
                    </button>
                  </div>
                ) : (
                  <div>
                    <div className="text-5xl mb-3">📂</div>
                    <p className="text-slate-400">Drop a file here or click to browse</p>
                    <p className="text-slate-600 text-sm mt-1">Max 10 MB · Images, PDFs, text, video</p>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Algorithm Selection */}
          <div className="card">
            <AlgorithmSelector selected={algorithms} onChange={setAlgorithms} />
          </div>

          {/* Crypto Params */}
          <div className="card">
            <CryptoInputs params={params} onChange={setParams} algorithms={algorithms} />
          </div>

          {/* Options */}
          <div className="card">
            <h2 className="section-title mb-3 text-base">⚙️ Options</h2>
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={captureSteps}
                onChange={e => setCaptureSteps(e.target.checked)}
                className="w-4 h-4 accent-primary-500"
              />
              <div>
                <div className="text-slate-300 text-sm font-medium">Capture internal steps</div>
                <div className="text-slate-500 text-xs">Enables step-by-step visualization (slower for large inputs)</div>
              </div>
            </label>
          </div>

          {/* Encrypt button */}
          <button
            onClick={handleEncrypt}
            disabled={loading}
            className="btn-primary w-full justify-center text-base py-3"
          >
            {loading ? (
              <>
                <span className="animate-spin">⟳</span>
                Encrypting...
              </>
            ) : (
              <>🔒 Encrypt</>
            )}
          </button>
        </div>

        {/* Right: Results */}
        <div className="xl:col-span-2 space-y-4">
          {results.length === 0 && !loading ? (
            <div className="card flex flex-col items-center justify-center py-20 text-center">
              <div className="text-6xl mb-4">🔐</div>
              <h3 className="text-xl font-semibold text-slate-300 mb-2">No Results Yet</h3>
              <p className="text-slate-500 max-w-sm">
                Configure your input, select algorithms, and provide a key/nonce to start encrypting.
              </p>
            </div>
          ) : loading ? (
            <div className="card flex flex-col items-center justify-center py-20">
              <div className="text-6xl mb-4 animate-pulse-slow">⚙️</div>
              <div className="text-slate-300 font-medium">Encrypting...</div>
              <div className="text-slate-500 text-sm mt-1">Running algorithms in parallel</div>
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <h2 className="section-title text-xl">
                  Results ({results.length} algorithm{results.length !== 1 ? 's' : ''})
                </h2>
              </div>
              {results.map((r, i) => (
                <EncryptionResult key={r.algorithm} result={r} index={i} />
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
