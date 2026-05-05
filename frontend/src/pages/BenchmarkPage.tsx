import { useState, useRef } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  LineChart, Line, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from 'recharts';
import toast from 'react-hot-toast';
import html2canvas from 'html2canvas';
import { runBenchmark, exportCsv, exportJson, benchmarkFile, BenchmarkRun, BenchmarkSuite } from '../services/api';
import clsx from 'clsx';

const ALGO_COLORS: Record<string, string> = {
  trivium:      '#3b82f6',
  grain128aead: '#10b981',
  mickey:       '#8b5cf6',
  chacha20:     '#f59e0b',
  ascon:        '#ef4444',
};

const DATA_SIZE_LABELS: Record<number, string> = {
  1024: '1 KB',
  16384: '16 KB',
  65536: '64 KB',
  262144: '256 KB',
};

type ChartType = 'bar-time' | 'bar-throughput' | 'line-trend' | 'radar';

export default function BenchmarkPage() {
  const [suite, setSuite] = useState<BenchmarkSuite | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedSize, setSelectedSize] = useState<number>(65536);
  const [chartType, setChartType] = useState<ChartType>('bar-throughput');
  const [selectedAlgos, setSelectedAlgos] = useState<string[]>(['trivium', 'grain128aead', 'mickey', 'chacha20', 'ascon']);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);
  const chartRef = useRef<HTMLDivElement>(null);

  const handleRunBenchmark = async () => {
    setLoading(true);
    try {
      const res = await runBenchmark({
        dataSizes: [1024, 16384, 65536, 262144],
      });
      setSuite(res.data);
      toast.success(`Benchmark tugadi! Eng tezkor: ${res.data.fastest}`);
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0] ?? null;
    setUploadFile(f);
  };

  const toggleAlgo = (algo: string) => {
    setSelectedAlgos(prev => prev.includes(algo) ? prev.filter(a => a !== algo) : [...prev, algo]);
  };

  const handleUploadBenchmark = async () => {
    if (!uploadFile) {
      toast.error('Iltimos, benchmark uchun fayl tanlang');
      return;
    }
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('file', uploadFile);
      if (selectedAlgos.length > 0) formData.append('algorithms', JSON.stringify(selectedAlgos));

      const res = await benchmarkFile(formData);
      const runs: BenchmarkRun[] = res.data;
      // convert to suite-like shape for UI
      const dataSizes = Array.from(new Set(runs.map(r => r.dataSize)));
      const largestSize = Math.max(...dataSizes);
      const largestRuns = runs.filter(r => r.dataSize === largestSize);
      const fastest = largestRuns.reduce((best, r) => r.throughputEnc > best.throughputEnc ? r : best).algorithm;
      const slowest = largestRuns.reduce((worst, r) => r.throughputEnc < worst.throughputEnc ? r : worst).algorithm;

      setSuite({ runs, dataSizes, timestamp: new Date().toISOString(), fastest, slowest });
      setSelectedSize(dataSizes[0] ?? uploadFile.size);
      setUploadedFileName(uploadFile.name);
      toast.success(`Fayl uchun benchmark tugadi: ${uploadFile.name}`);
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  // Generate same test payload as backend (pattern: i & 0xff)
  const generateTestData = (size: number): Uint8Array => {
    const data = new Uint8Array(size);
    for (let i = 0; i < size; i++) data[i] = i & 0xff;
    return data;
  };

  const downloadTestPayload = (size: number) => {
    const data = generateTestData(size);
    const arrayBuffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
    const blob = new Blob([arrayBuffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `benchmark_payload_${size}B.bin`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const previewUploadedFile = async () => {
    if (!uploadFile) return;
    const file = uploadFile;
    if (file.type.startsWith('image/') || file.type.startsWith('video/')) {
      const url = URL.createObjectURL(file);
      window.open(url, '_blank');
      // do not revoke immediately to allow user to view
    } else if (file.type.startsWith('text/') || file.name.endsWith('.txt') || file.type === 'application/json') {
      const text = await file.text();
      const w = window.open('', '_blank');
      if (w) {
        const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        w.document.body.style.background = '#0f172a';
        w.document.body.style.color = '#e2e8f0';
        w.document.title = file.name;
        w.document.body.innerHTML = `<pre style="white-space:pre-wrap;word-break:break-word;font-family:monospace">${esc(text)}</pre>`;
      }
    } else {
      // fallback to download
      const url = URL.createObjectURL(file);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const getRunsForSize = (size: number): BenchmarkRun[] => {
    if (!suite) return [];
    return suite.runs.filter(r => r.dataSize === size);
  };

  const getThroughputTrend = () => {
    if (!suite) return [];
    const algos = ['trivium', 'grain128aead', 'mickey', 'chacha20', 'ascon'];
    return suite.dataSizes.map(size => {
      const entry: Record<string, unknown> = { size: DATA_SIZE_LABELS[size] ?? `${size}B` };
      for (const algo of algos) {
        const run = suite.runs.find(r => r.dataSize === size && r.algorithm === algo);
        entry[algo] = run?.throughputEnc?.toFixed(3) ?? 0;
      }
      return entry;
    });
  };

  const getRadarData = () => {
    if (!suite) return [];
    const runs = getRunsForSize(selectedSize);
    const maxThroughput = Math.max(...runs.map(r => r.throughputEnc));
    const maxMem = Math.max(...runs.map(r => r.memoryUsed)) || 1;

    return runs.map(r => ({
      algorithm: r.algorithm,
      Throughput: Math.round((r.throughputEnc / maxThroughput) * 100),
      Speed: Math.round(100 - (r.encryptTime / Math.max(...runs.map(x => x.encryptTime))) * 100),
      Memory: Math.round(100 - (r.memoryUsed / maxMem) * 100),
      Security: { trivium: 75, grain128aead: 90, mickey: 75, chacha20: 95, ascon: 95 }[r.algorithm] ?? 80,
      IoTFit: { trivium: 95, grain128aead: 90, mickey: 85, chacha20: 70, ascon: 90 }[r.algorithm] ?? 80,
    }));
  };

  const downloadChart = async () => {
    if (!chartRef.current) return;
    try {
      const canvas = await html2canvas(chartRef.current, { backgroundColor: '#0f172a' });
      const url = canvas.toDataURL('image/png');
      const a = document.createElement('a');
      a.href = url;
      a.download = 'benchmark_chart.png';
      a.click();
      toast.success("Grafik yuklandi!");
    } catch {
      toast.error("Grafikni yuklab bo'lmadi");
    }
  };

  const currentRuns = getRunsForSize(selectedSize);

  return (
    <div className="space-y-8">
      <div>
          <h1 className="text-3xl font-bold text-slate-800 dark:text-slate-100 mb-2">
            📊 Ishlash sinovlari
          </h1>
        <p className="text-slate-400">Barcha algoritmlar bo'yicha shifrlash tezligi, o'tkazuvchanlik va xotira sarfini solishtiring</p>
      </div>

      {/* Controls */}
      <div className="card flex flex-wrap items-center gap-4">
        <button
          onClick={handleRunBenchmark}
          disabled={loading}
          className="btn-primary"
        >
          {loading ? <><span className="animate-spin">⟳</span> Ishlamoqda...</> : '▶ Sinovlarni ishga tushur'}
        </button>
        <div className="flex items-center gap-2">
          <input type="file" accept="*/*" onChange={handleFileChange} />
          <button onClick={handleUploadBenchmark} disabled={loading} className="btn-secondary">
            Komputerdan benchmark qilish
          </button>
        </div>
        <div className="flex items-center gap-2">
          {(['trivium','grain128aead','mickey','chacha20','ascon'] as const).map(a => (
            <button key={a} onClick={() => toggleAlgo(a)} className={selectedAlgos.includes(a) ? 'tab-active text-xs' : 'tab-inactive text-xs'}>{a}</button>
          ))}
        </div>
        {suite && (
          <>
            <span className="text-slate-500 text-sm">Tugatilgan vaqt: {new Date(suite.timestamp).toLocaleTimeString()}</span>
            {uploadedFileName && <span className="text-slate-400 text-sm">File: {uploadedFileName}</span>}
            <div className="ml-auto flex gap-2">
              <button
                onClick={() => exportCsv(suite.runs, 'benchmark_results')}
                className="btn-secondary text-sm"
              >
                📊 CSV
              </button>
              <button
                onClick={() => exportJson(suite, 'benchmark_results')}
                className="btn-secondary text-sm"
              >
                📦 JSON
              </button>
              <button onClick={downloadChart} className="btn-secondary text-sm">
                🖼 Save Chart
              </button>
            </div>
          </>
        )}
      </div>

      {suite ? (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Eng tez", value: suite.fastest, icon: '🚀', color: 'text-emerald-300' },
              { label: "Eng sekin", value: suite.slowest, icon: '🐢', color: 'text-amber-300' },
              { label: "Eng yaxshi xavfsizlik", value: 'ascon / chacha20', icon: '🔐', color: 'text-blue-300' },
              { label: "IoT uchun eng mos", value: 'trivium', icon: '📡', color: 'text-violet-300' },
            ].map(item => (
              <div key={item.label} className="card text-center">
                <div className="text-3xl mb-2">{item.icon}</div>
                <div className={clsx('font-semibold text-sm capitalize', item.color)}>{item.value}</div>
                <div className="text-slate-500 text-xs mt-1">{item.label}</div>
              </div>
            ))}
          </div>

          {/* Data size selector */}
          <div className="flex items-center gap-3">
            <span className="text-slate-400 text-sm">Ma'lumot hajmi:</span>
            {suite.dataSizes.map(size => (
              <button
                key={size}
                onClick={() => setSelectedSize(size)}
                className={selectedSize === size ? 'tab-active' : 'tab-inactive'}
              >
                {DATA_SIZE_LABELS[size] ?? `${size}Bayt `}
              </button>
            ))}
          </div>

          {/* Chart type tabs */}
          <div className="flex items-center gap-2">
              {([
              { id: 'bar-throughput', label: '📊 O\'tkazuvchanlik' },
              { id: 'bar-time', label: '⏱ Vaqt' },
              { id: 'line-trend', label: '📈 Tendensiya' },
              { id: 'radar', label: '🕸 Radar' },
            ] as const).map(c => (
              <button
                key={c.id}
                onClick={() => setChartType(c.id)}
                className={chartType === c.id ? 'tab-active' : 'tab-inactive'}
              >
                {c.label}
              </button>
            ))}
          </div>

          {/* Chart */}
          <div className="card" ref={chartRef}>
            <ResponsiveContainer width="100%" height={380}>
              {chartType === 'bar-throughput' ? (
                <BarChart data={currentRuns}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="algorithm" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} label={{ value: 'MB/s', angle: -90, position: 'insideLeft', fill: '#64748b' }} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', color: '#f1f5f9' }} />
                  <Legend wrapperStyle={{ color: '#94a3b8' }} />
                  <Bar dataKey="throughputEnc" name="Shifrlash (MB/s)" fill="#0ea5e9" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="throughputDec" name="Deshifrlash (MB/s)" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
                </BarChart>
              ) : chartType === 'bar-time' ? (
                <BarChart data={currentRuns}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="algorithm" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} label={{ value: 'ms', angle: -90, position: 'insideLeft', fill: '#64748b' }} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', color: '#f1f5f9' }} />
                  <Legend wrapperStyle={{ color: '#94a3b8' }} />
                  <Bar dataKey="encryptTime" name="Shifrlash (ms)" fill="#10b981" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="decryptTime" name="Deshifrlash (ms)" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                </BarChart>
              ) : chartType === 'line-trend' ? (
                <LineChart data={getThroughputTrend()}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="size" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                  <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} label={{ value: 'MB/s', angle: -90, position: 'insideLeft', fill: '#64748b' }} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', color: '#f1f5f9' }} />
                  <Legend wrapperStyle={{ color: '#94a3b8' }} />
                  {['trivium', 'grain128aead', 'mickey', 'chacha20', 'ascon'].map(algo => (
                    <Line key={algo} type="monotone" dataKey={algo} stroke={ALGO_COLORS[algo]} strokeWidth={2} dot={{ r: 4 }} />
                  ))}
                </LineChart>
              ) : (
                <RadarChart cx="50%" cy="50%" outerRadius="70%" data={getRadarData()}>
                  <PolarGrid stroke="#334155" />
                  <PolarAngleAxis dataKey="algorithm" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <PolarRadiusAxis tick={{ fill: '#64748b', fontSize: 10 }} domain={[0, 100]} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', color: '#f1f5f9' }} />
                  <Radar name="Shifrlash" dataKey="Throughput" stroke="#0ea5e9" fill="#0ea5e9" fillOpacity={0.2} />
                  <Radar name="Xavfsizlik" dataKey="Security" stroke="#10b981" fill="#10b981" fillOpacity={0.2} />
                  <Radar name="IoT Moslashuvchanlik" dataKey="IoTFit" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.2} />
                  <Legend wrapperStyle={{ color: '#94a3b8' }} />
                </RadarChart>
              )}
            </ResponsiveContainer>
          </div>

            {/* Files tested panel */}
            <div className="card">
              <h3 className="section-title mb-3">📁 Sinov qilingan fayllar</h3>
              {uploadedFileName ? (
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium">{uploadedFileName}</div>
                    <div className="text-slate-500 text-xs">Fayl siz tomonidan yuklangan</div>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={previewUploadedFile} className="btn-secondary text-sm">👁 Ko'rish</button>
                    <button onClick={() => {
                      if (!uploadFile) return; const url = URL.createObjectURL(uploadFile); const a = document.createElement('a'); a.href = url; a.download = uploadFile.name; a.click(); URL.revokeObjectURL(url);
                    }} className="btn-secondary text-sm">⬇ Yuklab olish</button>
                  </div>
                </div>
              ) : (
                <div>
                  <div className="text-slate-400 text-sm mb-2">To'liq to'plamli benchmarking uchun ishlatiladigan o'rnatilgan sintetik yuklamalar:</div>
                  <div className="flex flex-wrap gap-2">
                    {Object.keys(DATA_SIZE_LABELS).map(k => {
                      const size = Number(k);
                      return (
                        <div key={k} className="p-2 bg-dark-900/60 rounded flex items-center gap-3">
                          <div className="text-slate-200 font-mono">{DATA_SIZE_LABELS[size]}</div>
                          <button onClick={() => downloadTestPayload(size)} className="text-xs btn-secondary">⬇ Yuklab olish</button>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

          {/* Detailed table */}
          <div className="card overflow-x-auto">
            <h2 className="section-title mb-4">📋 Batafsil natijalar — {DATA_SIZE_LABELS[selectedSize]}</h2>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700/50">
                  {['Algoritm', "Shifrlash vaqti", "Deshifrlash vaqti", "Shifrlash o'tkazuvchanligi", "Deshifrlash o'tkazuvchanligi", 'Xotira', 'CPU%'].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-slate-400 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {currentRuns
                  .sort((a, b) => b.throughputEnc - a.throughputEnc)
                  .map((run, i) => (
                    <tr key={run.algorithm} className={clsx(
                      'border-b border-slate-800/50 hover:bg-slate-700/20 transition-colors',
                      i === 0 && 'bg-emerald-500/5'
                    )}>
                      <td className="py-3 px-3 font-medium text-slate-200 capitalize flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ background: ALGO_COLORS[run.algorithm] }}></span>
                        {run.algorithm}
                        {i === 0 && <span className="badge-green text-xs">Eng tez</span>}
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-300">{run.encryptTime.toFixed(3)} ms</td>
                      <td className="py-3 px-3 font-mono text-slate-300">{run.decryptTime.toFixed(3)} ms</td>
                      <td className="py-3 px-3 font-mono text-primary-300">{run.throughputEnc.toFixed(4)} MB/s</td>
                      <td className="py-3 px-3 font-mono text-violet-300">{run.throughputDec.toFixed(4)} MB/s</td>
                      <td className="py-3 px-3 font-mono text-slate-400">{run.memoryUsed.toFixed(2)} MB</td>
                      <td className="py-3 px-3 font-mono text-amber-300">{run.cpuApprox.toFixed(2)}%</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <div className="card flex flex-col items-center justify-center py-24 text-center">
          <div className="text-6xl mb-4">📊</div>
          <h3 className="text-xl font-semibold text-slate-300 mb-2">Benchmark Data yo'q</h3>
          <p className="text-slate-500 max-w-md mb-6">
            4 ta ma'lumot o'lchamida (1KB, 16KB, 64KB, 256KB) barcha 5 ta algoritmni sinab ko'rish uchun "Benchmarkni ishga tushirish" tugmasini bosing. Natijalar o'tkazish qobiliyati, kechikish va xotira profilini o'z ichiga oladi.
          </p>
          <button onClick={handleRunBenchmark} disabled={loading} className="btn-primary px-8">
            {loading ? <><span className="animate-spin">⟳</span> Running...</> : '▶ Benchmarkni hozir ishga tushirish'}
          </button>
        </div>
      )}
    </div>
  );
}
