import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import toast from 'react-hot-toast';
import clsx from 'clsx';
import { decryptText, decryptFromFile, DecryptResult } from '../services/api';
import CryptoInputs, { CryptoParams } from '../components/CryptoInputs';

const ALGORITHMS = [
  { id: 'trivium', name: 'Trivium' },
  { id: 'grain128aead', name: 'Grain-128AEAD' },
  { id: 'mickey', name: 'MICKEY-v2' },
  { id: 'chacha20', name: 'ChaCha20' },
  { id: 'ascon', name: 'Ascon-AEAD128' },
];

type InputMode = 'manual' | 'file';

export default function DecryptPage() {
  const [inputMode, setInputMode] = useState<InputMode>('manual');
  const [algorithm, setAlgorithm] = useState('chacha20');
  const [ciphertext, setCiphertext] = useState('');
  const [ciphertextEncoding, setCiphertextEncoding] = useState<'hex' | 'base64'>('hex');
  const [tag, setTag] = useState('');
  const [params, setParams] = useState<CryptoParams>({ key: '', nonce: '', aad: '' });
  const [result, setResult] = useState<DecryptResult | null>(null);
  const [parsedFile, setParsedFile] = useState<Record<string, string> | null>(null);
  const [loading, setLoading] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [originalFilenameField, setOriginalFilenameField] = useState('');
  const [originalMimeTypeField, setOriginalMimeTypeField] = useState('');

  const onDrop = useCallback((accepted: File[]) => {
    if (accepted[0]) setFile(accepted[0]);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'text/plain': ['.txt'] },
    maxSize: 15 * 1024 * 1024,
    multiple: false,
  });

  const handleDecrypt = async () => {
    setLoading(true);
    setResult(null);
    setParsedFile(null);

    try {
      if (inputMode === 'file' && file) {
        const formData = new FormData();
        formData.append('file', file);
        const res = await decryptFromFile(formData);
        setResult(res.data);
        setParsedFile(res.parsedFile);
        toast.success("Fayl muvaffaqiyatli deshifrlandi!");
      } else {
        if (!ciphertext.trim()) throw new Error("Iltimos, shifrlangan matn kiriting");
        if (!params.key || !params.nonce) throw new Error("Iltimos, kalit va nonce kiriting");

        const res = await decryptText({
          algorithm,
          ciphertext,
          ciphertextEncoding,
          key: params.key,
          nonce: params.nonce,
          aad: params.aad || undefined,
          tag: tag || undefined,
          originalFilename: originalFilenameField || undefined,
          originalMimeType: originalMimeTypeField || undefined,
        });
        setResult(res.data);
        setParsedFile(res.parsedFile ?? null);
        toast.success("Deshifrlash muvaffaqiyatli bajarildi!");
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
        <h1 className="text-3xl font-bold text-slate-800 dark:text-slate-100 mb-2">
          🔓 Deshifrlash
        </h1>
        <p className="text-slate-400">Shifrlangan matnni qo'lda yoki saqlangan hisobotdan deshifrlash</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        {/* Configuration */}
        <div className="space-y-6">
          {/* Input mode tabs */}
          <div className="card">
            <div className="flex gap-2 mb-4">
                {(['manual', 'file'] as const).map(mode => (
                <button
                  key={mode}
                  onClick={() => setInputMode(mode)}
                  className={inputMode === mode ? 'tab-active' : 'tab-inactive'}
                >
                  {mode === 'manual' ? "✏️ Qo'lda" : '📄 Hisobot faylidan'}
                </button>
              ))}
            </div>

            {inputMode === 'manual' ? (
              <div className="space-y-4">
                {/* Algorithm */}
                <div>
                  <label className="label">Algoritm</label>
                  <select
                    value={algorithm}
                    onChange={e => setAlgorithm(e.target.value)}
                    className="input-field"
                  >
                    {ALGORITHMS.map(a => (
                      <option key={a.id} value={a.id}>{a.name}</option>
                    ))}
                  </select>
                </div>

                {/* Ciphertext */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="label mb-0">Shifrlangan matn</label>
                    <div className="flex gap-2">
                      {(['hex', 'base64'] as const).map(enc => (
                        <button
                          key={enc}
                          onClick={() => setCiphertextEncoding(enc)}
                          className={clsx(
                            'text-xs px-2 py-1 rounded transition-colors',
                            ciphertextEncoding === enc
                              ? 'bg-primary-600 text-white'
                              : 'text-slate-400 hover:text-slate-200'
                          )}
                        >
                          {enc}
                        </button>
                      ))}
                    </div>
                  </div>
                  <textarea
                    value={ciphertext}
                    onChange={e => setCiphertext(e.target.value)}
                    className="input-field min-h-[100px] resize-y"
                    placeholder={ciphertextEncoding === 'hex' ? 'Hex formatdagi shifrlangan matnni joylashtiring...' : 'Base64 formatdagi shifrlangan matnni joylashtiring...'}
                  />
                </div>

                {/* Auth tag (for AEAD) */}
                {['grain128aead', 'ascon'].includes(algorithm) && (
                  <div>
                    <label className="label">
                      Autentifikatsiya tegi
                      <span className="badge-purple ml-2">AEAD</span>
                    </label>
                    <input
                      type="text"
                      value={tag}
                      onChange={e => setTag(e.target.value)}
                      className="input-field"
                      placeholder="Tekshirish uchun hex formatdagi autentifikatsiya tegi"
                    />
                  </div>
                )}

                {/* Optional original file metadata for reconstructing binary files */}
                <div>
                  <label className="label">Asl fayl nomi (ixtiyoriy)</label>
                  <input
                    type="text"
                    value={originalFilenameField}
                    onChange={e => setOriginalFilenameField(e.target.value)}
                    className="input-field"
                    placeholder="misol: image.png"
                  />
                </div>
                <div>
                  <label className="label">Asl MIME turi (ixtiyoriy)</label>
                  <input
                    type="text"
                    value={originalMimeTypeField}
                    onChange={e => setOriginalMimeTypeField(e.target.value)}
                    className="input-field"
                    placeholder="misol: image/png"
                  />
                </div>
              </div>
            ) : (
              <div>
                <p className="text-slate-400 text-sm mb-3">
                  Shifrlash vositasi tomonidan yaratilgan .txt hisobot faylini yuklang. Algoritm va shifrlangan matn avtomatik aniqlanadi.
                </p>
                <div
                  {...getRootProps()}
                  className={clsx(
                    'border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all',
                    isDragActive ? 'border-primary-400 bg-primary-500/10' : 'border-slate-700 hover:border-slate-500'
                  )}
                >
                  <input {...getInputProps()} />
                  {file ? (
                    <div>
                      <div className="text-3xl mb-2">📄</div>
                      <div className="text-slate-200 font-medium">{file.name}</div>
                      <button
                        onClick={e => { e.stopPropagation(); setFile(null); }}
                        className="text-red-400 text-xs mt-2 hover:text-red-300"
                      >
                        O'chirish
                      </button>
                    </div>
                  ) : (
                    <div>
                      <div className="text-4xl mb-2">📂</div>
                      <p className="text-slate-400">Bu yerga .txt hisobot faylini tashlang</p>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Key/Nonce (only for manual mode) */}
          {inputMode === 'manual' && (
            <div className="card">
              <CryptoInputs
                params={params}
                onChange={setParams}
                algorithms={[algorithm]}
                showAad
              />
            </div>
          )}

          <button
            onClick={handleDecrypt}
            disabled={loading}
            className="btn-primary w-full justify-center text-base py-3"
          >
            {loading ? <><span className="animate-spin">⟳</span> Deshifrlanmoqda...</> : '🔓 Deshifrlash'}
          </button>
        </div>

        {/* Result */}
        <div>
          {result ? (
            <div className="card space-y-5">
              <div className="flex items-center gap-3">
                <h2 className="section-title">🔓 Deshifrlash natijasi</h2>
                {result.valid === true && (
                  <span className="badge-green">✅ Teg to'g'ri</span>
                )}
                {result.valid === false && (
                  <span className="badge-red">❌ Teg noto'g'ri</span>
                )}
              </div>

              {/* Stats */}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-dark-900/60 border border-slate-700/30 rounded-lg p-3 text-center">
                  <div className="text-emerald-300 font-semibold">{result.timeTaken.toFixed(3)} ms</div>
                  <div className="text-slate-500 text-xs mt-1">Deshifrlash vaqti</div>
                </div>
                <div className="bg-dark-900/60 border border-slate-700/30 rounded-lg p-3 text-center">
                  <div className="text-slate-200 font-semibold capitalize">{result.algorithm}</div>
                  <div className="text-slate-500 text-xs mt-1">Algoritm</div>
                </div>
              </div>

              {/* Parsed file info */}
              {parsedFile && (
                <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
                  <div className="text-amber-300 font-semibold text-sm mb-2">📄 Hisobotdan o'qildi</div>
                  {Object.entries(parsedFile).slice(0, 6).map(([k, v]) => (
                    <div key={k} className="text-xs text-slate-400 flex gap-2">
                      <span className="text-slate-500 min-w-24 capitalize">{k.replace(/_/g, ' ')}:</span>
                      <span className="font-mono break-all">{v.length > 40 ? v.slice(0, 40) + '...' : v}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Plaintext output */}
              <div className="bg-dark-950/50 border border-emerald-500/30 rounded-lg p-4 max-h-64 overflow-auto">
                  <pre className="text-slate-200 text-sm whitespace-pre-wrap break-words">
                    {result.plaintext}
                  </pre>
              </div>

              {/* Base64 */}
            <div className="bg-dark-950/50 border border-slate-700 rounded-lg p-3 max-h-40 overflow-auto">
              <pre className="text-xs text-slate-200 font-mono whitespace-pre-wrap break-all">
                {result.plaintextBase64}
              </pre>
            </div>

              {/* Copy buttons */}
              <div className="flex gap-2">
                <button
                  onClick={() => { navigator.clipboard.writeText(result.plaintext); toast.success("Matn nusxalandi!"); }}
                  className="btn-secondary text-sm"
                >
                  📋 Matnni nusxalash
                </button>
                <button
                  onClick={() => {
                    try {
                      if (result.plaintextBase64) {
                        const b64 = result.plaintextBase64;
                        const byteCharacters = atob(b64);
                        const byteNumbers = new Array(byteCharacters.length);
                        for (let i = 0; i < byteCharacters.length; i++) {
                          byteNumbers[i] = byteCharacters.charCodeAt(i);
                        }
                        const byteArray = new Uint8Array(byteNumbers);
                        const mime = parsedFile?.['original_mime_type'] || parsedFile?.['originalmimetype'] || 'application/octet-stream';
                        const filename = parsedFile?.['original_filename'] || parsedFile?.['originalfilename'] || 'decrypted_output';
                        const arrayBuffer = byteArray.buffer.slice(byteArray.byteOffset, byteArray.byteOffset + byteArray.byteLength) as ArrayBuffer;
                        const blob = new Blob([arrayBuffer], { type: mime });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = filename;
                        a.click();
                        URL.revokeObjectURL(url);
                      } else {
                        const blob = new Blob([result.plaintext], { type: 'text/plain' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = 'decrypted_output.txt';
                        a.click();
                        URL.revokeObjectURL(url);
                      }
                    } catch (e) {
                      toast.error('Faylni yuklab olish muvaffaqiyatsiz');
                    }
                  }}
                  className="btn-secondary text-sm"
                >
                  💾 Yuklab olish
                </button>
              </div>
            </div>
          ) : (
            <div className="card flex flex-col items-center justify-center py-20 text-center">
              <div className="text-6xl mb-4">🔓</div>
              <h3 className="text-xl font-semibold text-slate-300 mb-2">Deshifrlashga tayyor</h3>
              <p className="text-slate-500 max-w-sm">
                Shifrlangan matnni joylashtiring yoki .txt hisobotni yuklang, so'ngra kalit va nonce kiriting.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
