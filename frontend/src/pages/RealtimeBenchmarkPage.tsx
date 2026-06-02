import React, { useEffect, useRef, useState } from 'react';
import { LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, BarChart, Bar } from 'recharts';
import toast from 'react-hot-toast';

// Import ChaCha20 for inline encryption of media frames
import { chaCha20Encrypt, chaCha20Decrypt } from '../algorithms/chacha20';

// Worker (bundled by Vite)
const BenchmarkWorker = new Worker(new URL('../workers/benchmarkWorker.ts', import.meta.url), { type: 'module' });
console.log("[BENCHMARK] Worker started");
console.log('[BENCHMARK] Worker created');

function debugLog(...args: unknown[]) {
  console.log('[RealtimeBenchmark]', ...args);
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, '').trim();
  const len = clean.length / 2;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function makeNonceFromTimestamp(ts: number): Uint8Array {
  // 12 bytes: 8 bytes timestamp (big-endian) + 4 bytes zeros
  const buf = new ArrayBuffer(12);
  const dv = new DataView(buf);
  // ts may be large, convert to BigInt
  const t = BigInt(Math.floor(ts));
  dv.setBigUint64(0, t);
  dv.setUint32(8, 0);
  return new Uint8Array(buf);
}

const FRAME_META_MAGIC = 0xc1;
const FRAME_META_SIZE = 13;
const MAX_SAMPLES = 100;
const MAX_HISTORY_MS = 60_000;
const MAX_EXPORT_CIPHERTEXT_HEX = 8000;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function sliceHex(hex: string): string {
  return hex.length > MAX_EXPORT_CIPHERTEXT_HEX ? `${hex.slice(0, MAX_EXPORT_CIPHERTEXT_HEX)}...` : hex;
}

function withFrameMetadata(payload: Uint8Array, captureTs: number): Uint8Array {
  const out = new Uint8Array(FRAME_META_SIZE + payload.length);
  out[0] = FRAME_META_MAGIC;
  const view = new DataView(out.buffer);
  view.setFloat64(1, captureTs);
  view.setUint32(9, payload.length);
  out.set(payload, FRAME_META_SIZE);
  return out;
}

function extractFrameMetadata(payload: Uint8Array): { captureTs: number; media: Uint8Array } | null {
  if (payload.length < FRAME_META_SIZE) return null;
  if (payload[0] !== FRAME_META_MAGIC) return null;
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const captureTs = view.getFloat64(1);
  const bodyLen = view.getUint32(9);
  if (FRAME_META_SIZE + bodyLen > payload.length) return null;
  return { captureTs, media: payload.slice(FRAME_META_SIZE, FRAME_META_SIZE + bodyLen) };
}

function pruneRolling<T extends { ts: number }>(arr: T[]): T[] {
  const cutoff = Date.now() - MAX_HISTORY_MS;
  while (arr.length > MAX_SAMPLES) arr.shift();
  while (arr.length && arr[0].ts < cutoff) arr.shift();
  return arr;
}

export default function RealtimeBenchmarkPage() {
  const localVideoRef = useRef<HTMLVideoElement | null>(null);
  const remoteVideoRef = useRef<HTMLVideoElement | null>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const localStreamRef = useRef<MediaStream | null>(null);
  const [roomId, setRoomId] = useState<string>('');
  const [currentRoom, setCurrentRoom] = useState<string | null>(null);
  const [connectedPeer, setConnectedPeer] = useState<boolean>(false);
  const [roomKeyHex, setRoomKeyHex] = useState<string | null>(null);
  const [stats, setStats] = useState<Record<string, { encrypt: number; decrypt: number; throughput: number; latency: number }>>({});
  const [historyPoints, setHistoryPoints] = useState<Array<Record<string, number | string>>>(
    []
  );
  const [wsStatus, setWsStatus] = useState<string>('UZILGAN');

  const currentRoomRef = useRef<string | null>(null);
  const roomKeyHexRef = useRef<string | null>(null);

  const updateCurrentRoom = (val: string | null) => {
    setCurrentRoom(val);
    currentRoomRef.current = val;
  };

  const updateRoomKeyHex = (val: string | null) => {
    setRoomKeyHex(val);
    roomKeyHexRef.current = val;
  };

  const resultsBufferRef = useRef<Record<string, Array<{ ts: number; enc: number; dec: number; th: number; latency: number }>>>({});
  const benchmarkByFrameRef = useRef<Map<string, Record<string, { encrypt: number; decrypt: number; throughput: number; ciphertextHex: string; captureTs: number }>>>(new Map());
  const exportSnapshotRef = useRef<Record<string, { ts: number; ciphertextHex: string; encrypt: number; decrypt: number; throughput: number; latency: number }>>({});

  useEffect(() => {
    BenchmarkWorker.onmessage = (ev) => {
      const msg = ev.data;
      console.log("[BENCHMARK] Results received", msg);
      if (msg.type !== 'result') return;
      for (const r of msg.results) {
        const frameMap = benchmarkByFrameRef.current.get(r.frameId) ?? {};
        frameMap[r.algorithm] = {
          encrypt: r.encryptTime,
          decrypt: r.decryptTime,
          throughput: r.throughput,
          ciphertextHex: r.ciphertextHex,
          captureTs: r.captureTs,
        };
        benchmarkByFrameRef.current.set(r.frameId, frameMap);
      }
    };

    const interval = setInterval(() => {
      const staleCutoff = Date.now() - MAX_HISTORY_MS;
      for (const [frameId] of benchmarkByFrameRef.current.entries()) {
        const numeric = Number(frameId);
        if (!Number.isNaN(numeric) && numeric < staleCutoff) {
          benchmarkByFrameRef.current.delete(frameId);
        }
      }

      const out: Record<string, { encrypt: number; decrypt: number; throughput: number; latency: number }> = {};
      const cutoff = Date.now() - 1000;
      for (const algo of Object.keys(resultsBufferRef.current)) {
        const arr = pruneRolling(resultsBufferRef.current[algo]);
        const recent = arr.filter(x => x.ts >= cutoff);
        if (recent.length === 0) continue;
        const enc = recent.reduce((s, v) => s + v.enc, 0) / recent.length;
        const dec = recent.reduce((s, v) => s + v.dec, 0) / recent.length;
        const th = recent.reduce((s, v) => s + v.th, 0) / recent.length;
        const latency = recent.reduce((s, v) => s + v.latency, 0) / recent.length;
        out[algo] = {
          encrypt: parseFloat(enc.toFixed(3)),
          decrypt: parseFloat(dec.toFixed(3)),
          throughput: parseFloat(th.toFixed(3)),
          latency: parseFloat(latency.toFixed(3)),
        };
      }
      setStats(out);

      const point: Record<string, string | number> = { ts: Date.now(), label: new Date().toLocaleTimeString() };
      const algos = ['chacha20', 'mickey', 'ascon', 'grain128aead', 'trivium'];
      for (const algo of algos) {
        const s = out[algo];
        point[`${algo}_enc`] = s?.encrypt ?? 0;
        point[`${algo}_dec`] = s?.decrypt ?? 0;
        point[`${algo}_th`] = s?.throughput ?? 0;
        point[`${algo}_lat`] = s?.latency ?? 0;
      }
      setHistoryPoints(prev => pruneRolling([...prev, point as any]));
      console.log("[BENCHMARK] State updated");
    }, 1000);

    return () => {
      clearInterval(interval);
      BenchmarkWorker.terminate();
    };
  }, []);

  async function startLocalMedia() {
    try {
      const s = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      localStreamRef.current = s;
      if (localVideoRef.current) localVideoRef.current.srcObject = s;
    } catch (err) {
      toast.error('Failed to access camera/microphone');
    }
  }

  useEffect(() => {
    startLocalMedia();
    ensureWebSocket();
  }, []);

  useEffect(() => {
    const hasInsertable = !!((window as any).RTCRtpSender && typeof (RTCRtpSender as any).prototype.createEncodedStreams === 'function');
    console.log('[BENCHMARK] Insertable Streams support:', hasInsertable);
  }, []);

  function ensureWebSocket() {
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      console.debug('[ensureWebSocket] returning existing socket, readyState=', wsRef.current.readyState);
      return wsRef.current;
    }

    const envUrl = (import.meta.env.VITE_WS_URL as string) ?? '';
    const defaultHost = window.location.host;
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
    
    let wsUrl = envUrl;
    if (!wsUrl) {
      if (defaultHost.includes(':5173')) {
        wsUrl = `${scheme}://${window.location.hostname}:3099/ws`;
      } else {
        wsUrl = `${scheme}://${defaultHost}/ws`;
      }
    }
    
    debugLog('ensureWebSocket - creating WebSocket to', wsUrl);
    const ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';
    setWsStatus('ULANMOQDA');

    ws.addEventListener('open', () => {
      console.log('[RealtimeBenchmark] websocket open');
      setWsStatus('ULANGAN');
    });

    ws.addEventListener('message', (ev) => {
      try {
        console.log('[RealtimeBenchmark] websocket receive', ev.data);
        handleWsMessage(ev as MessageEvent);
      } catch (err) {
        debugLog('WS message handler error', err);
      }
    });

    ws.addEventListener('close', (ev) => {
      console.log('[RealtimeBenchmark] websocket close', ev);
      wsRef.current = null;
      setWsStatus('UZILGAN');
      toast.error('Signaling connection closed');
    });

    ws.addEventListener('error', (ev) => {
      console.log('[RealtimeBenchmark] websocket error', ev);
      setWsStatus('ERROR');
      toast.error('Signaling connection error');
    });

    wsRef.current = ws;
    return ws;
  }

  function sendSignalingMessage(obj: unknown) {
    try {
      const ws = ensureWebSocket();
      if (!ws) {
        toast.error('No signaling connection available');
        return false;
      }
      const state = ws.readyState;
      const payload = JSON.stringify(obj);

      if (state === WebSocket.OPEN) {
        ws.send(payload);
        console.log('[RealtimeBenchmark] websocket send', payload);
        return true;
      }

      if (state === WebSocket.CONNECTING) {
        console.log('[RealtimeBenchmark] WS connecting - will send on open', payload);
        const onOpen = () => {
          try {
            ws.send(payload);
            console.log('[RealtimeBenchmark] websocket send', payload);
          } catch (e) {
            console.error('[RealtimeBenchmark] send on open failed', e);
          }
          ws.removeEventListener('open', onOpen);
        };
        ws.addEventListener('open', onOpen);
        // set fallback timeout
        setTimeout(() => {
          if (ws.readyState !== WebSocket.OPEN) {
            console.warn('[RealtimeBenchmark] WS did not open in time for message', obj);
            toast.error('Signaling not ready');
          }
        }, 5000);
        return true;
      }

      console.warn('[RealtimeBenchmark] WebSocket is not OPEN (readyState = ' + state + ')');
      toast.error('Signaling connection is not active (status: ' + state + ')');
      return false;
    } catch (err) {
      console.error('[RealtimeBenchmark] sendSignalingMessage error', err);
      toast.error('Failed to send signaling message');
      return false;
    }
  }

  function handleWsMessage(ev: MessageEvent) {
    let msg: any;
    try {
      msg = JSON.parse(ev.data);
    } catch (e) {
      debugLog('handleWsMessage - invalid json', ev.data);
      return;
    }
    debugLog('handleWsMessage - type=', msg.type, 'payload=', msg);
    switch (msg.type) {
      case 'created':
        updateCurrentRoom(msg.roomId);
        updateRoomKeyHex(msg.keyHex);
        console.log('[RealtimeBenchmark] room created', msg.roomId);
        toast.success(`Tarmoq yaratildi: ${msg.roomId}`);
        if (pcRef.current) tryAttachTransforms(pcRef.current);
        break;
      case 'joined':
        updateCurrentRoom(msg.roomId);
        updateRoomKeyHex(msg.keyHex);
        console.log('[RealtimeBenchmark] room joined', msg.roomId);
        toast.success(`Tarmoqga kirildi: ${msg.roomId}`);
        if (pcRef.current) tryAttachTransforms(pcRef.current);
        break;
      case 'peer-joined':
        setConnectedPeer(true);
        toast.success('Foydalanuvchi ulandi');
        // ensure PC exists then start negotiation
        if (!pcRef.current) {
          createPeerConnection().then(() => createAndSendOffer()).catch(e => debugLog('createPeerConnection failed', e));
        } else {
          if (pcRef.current.signalingState === 'stable') createAndSendOffer();
          else createAndSendOffer();
        }
        break;
      case 'peer-left':
        setConnectedPeer(false);
        break;
      case 'signal':
        debugLog('signal message', msg.data);
        if (msg.data?.type === 'offer') onReceiveOffer(msg.data.sdp);
        else if (msg.data?.type === 'answer') onReceiveAnswer(msg.data.sdp);
        else if (msg.data?.type === 'ice') onReceiveIce(msg.data.candidate);
        break;
      case 'error':
        toast.error(msg.message || 'Signaling error');
        break;
      default:
        break;
    }
  }

  async function createAndSendOffer() {
    const pc = pcRef.current!;
    if (!pc) return;
    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      console.log('[RealtimeBenchmark] offer created');
      sendSignalingMessage({ type: 'signal', roomId: currentRoomRef.current, data: { type: 'offer', sdp: offer.sdp } });
    } catch (err) { console.error(err); }
  }

  async function onReceiveOffer(sdp: string) {
    if (!pcRef.current) await createPeerConnection();
    const pc = pcRef.current!;
    await pc.setRemoteDescription({ type: 'offer', sdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    debugLog('onReceiveOffer - sending answer');
    sendSignalingMessage({ type: 'signal', roomId: currentRoomRef.current, data: { type: 'answer', sdp: answer.sdp } });
  }

  async function onReceiveAnswer(sdp: string) {
    console.log('[RealtimeBenchmark] answer received');
    const pc = pcRef.current;
    if (!pc) return;
    await pc.setRemoteDescription({ type: 'answer', sdp });
  }

  async function onReceiveIce(candidate: any) {
    console.log('[RealtimeBenchmark] ICE candidate received', candidate);
    const pc = pcRef.current;
    if (!pc || !candidate) return;
    try { await pc.addIceCandidate(candidate); } catch (err) { console.warn('Invalid ICE candidate', err); }
  }

  async function createPeerConnection() {
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
      encodedInsertableStreams: true, // Enable Insertable Streams
    } as any);
    pcRef.current = pc;

    pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        console.log('[RealtimeBenchmark] ICE candidate sent', ev.candidate);
        sendSignalingMessage({ type: 'signal', roomId: currentRoomRef.current, data: { type: 'ice', candidate: ev.candidate } });
      }
    };

    pc.ontrack = (ev) => {
      if (remoteVideoRef.current) remoteVideoRef.current.srcObject = ev.streams[0];
      console.log('[RealtimeBenchmark] ontrack received, attaching receiver transform');
      tryAttachTransforms(pc);
    };

    // Add local tracks
    if (localStreamRef.current) {
      for (const track of localStreamRef.current.getTracks()) {
        const sender = pc.addTrack(track, localStreamRef.current);
      }
    }

    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'connected') {
        setConnectedPeer(true);
        console.log('[RealtimeBenchmark] connectionState connected, attaching transforms');
        tryAttachTransforms(pc);
      }
      if (pc.connectionState === 'disconnected' || pc.connectionState === 'closed') setConnectedPeer(false);
    };

    // Attach Insertable Streams transforms if available
    tryAttachTransforms(pc);
    setTimeout(() => {
      tryAttachTransforms(pc);
    }, 500);
    setTimeout(() => {
      tryAttachTransforms(pc);
    }, 1500);

    return pc;
  }

  function tryAttachTransforms(pc: RTCPeerConnection) {
    const keyHex = roomKeyHexRef.current;
    if (!keyHex) {
      console.log('[RealtimeBenchmark] tryAttachTransforms - no roomKeyHex yet, skipping attach');
      return;
    }
    const key = hexToBytes(keyHex);

    // Sender side transform (encrypt before sending)
    const senders = pc.getSenders();
    for (const sender of senders) {
      if (!sender.track || (sender as any).hasTransformAttached) continue;
      try {
        const cs = (sender as any).createEncodedStreams?.();
        if (!cs) {
          console.log('[BENCHMARK] sender.createEncodedStreams not available for track', sender.track?.kind);
          continue;
        }
        (sender as any).hasTransformAttached = true;
        console.log('[RealtimeBenchmark] Attaching transform to sender for track:', sender.track.kind);
        const transformer = new TransformStream({
          transform: (chunk: any, controller: any) => {
            try {
              const rawData = new Uint8Array(chunk.data);
              const captureTs = Date.now();
              const frameId = `${Math.floor(captureTs)}`;
              console.log('[BENCHMARK] Chunk captured (insertable) size=', rawData.byteLength, 'frameId=', frameId);

              const payload = withFrameMetadata(rawData, captureTs);
              const nonce = makeNonceFromTimestamp(chunk.timestamp ?? captureTs);
              const encStart = performance.now();
              const res = chaCha20Encrypt(payload, key, nonce);
              const encMs = performance.now() - encStart;
              console.log('[ENCRYPT] frameId=', frameId, 'encryptMs=', encMs.toFixed(4), 'size=', payload.byteLength);
              chunk.data = res.ciphertext.buffer;

              const copy = rawData.slice().buffer;
              BenchmarkWorker.postMessage({ type: 'benchmark', data: copy, frameId, captureTs }, [copy]);
              exportSnapshotRef.current.chacha20 = {
                ts: Date.now(),
                ciphertextHex: sliceHex(bytesToHex(res.ciphertext)),
                encrypt: encMs,
                decrypt: 0,
                throughput: (payload.byteLength / (1024 * 1024)) / (encMs / 1000 || 1),
                latency: 0,
              };
            } catch (err) {
              // pass through on error
            }
            controller.enqueue(chunk);
          }
        });
        cs.readable.pipeThrough(transformer).pipeTo(cs.writable);
      } catch (err) { console.warn('Failed to attach sender transform', err); }
    }

    // Receiver side transform (decrypt before decode)
    const receivers = pc.getReceivers();
    for (const receiver of receivers) {
      if (!receiver.track || (receiver as any).hasTransformAttached) continue;
      try {
        const cs = (receiver as any).createEncodedStreams?.();
        if (!cs) {
          console.log('[BENCHMARK] receiver.createEncodedStreams not available for track', receiver.track?.kind);
          continue;
        }
        (receiver as any).hasTransformAttached = true;
        console.log('[RealtimeBenchmark] Attaching transform to receiver for track:', receiver.track.kind);
        const transformer = new TransformStream({
          transform: (chunk: any, controller: any) => {
            try {
              const encrypted = new Uint8Array(chunk.data);
              const nonce = makeNonceFromTimestamp(chunk.timestamp ?? Date.now());
              const decStart = performance.now();
              const dec = chaCha20Decrypt(encrypted, key, nonce);
              const decMs = performance.now() - decStart;
              const meta = extractFrameMetadata(dec.ciphertext);
              if (meta) {
                const endTs = Date.now();
                const chachaLatency = endTs - meta.captureTs;
                const networkBase = Math.max(0, chachaLatency - decMs);
                console.log('[DECRYPT] latencyMs=', chachaLatency.toFixed(4), 'decryptMs=', decMs.toFixed(4), 'mediaSize=', meta.media.byteLength);
                console.log('[LATENCY] baseNetworkMs=', networkBase.toFixed(4));

                // Update ChaCha row from true transmission path.
                if (!resultsBufferRef.current.chacha20) resultsBufferRef.current.chacha20 = [];
                resultsBufferRef.current.chacha20.push({
                  ts: endTs,
                  enc: exportSnapshotRef.current.chacha20?.encrypt ?? 0,
                  dec: decMs,
                  th: exportSnapshotRef.current.chacha20?.throughput ?? 0,
                  latency: chachaLatency,
                });
                pruneRolling(resultsBufferRef.current.chacha20);
                if (exportSnapshotRef.current.chacha20) {
                  exportSnapshotRef.current.chacha20 = {
                    ...exportSnapshotRef.current.chacha20,
                    ts: endTs,
                    decrypt: decMs,
                    latency: chachaLatency,
                  };
                }

                const frameKey = `${Math.floor(meta.captureTs)}`;
                const pending = benchmarkByFrameRef.current.get(frameKey);
                if (pending) {
                  for (const [algorithm, metrics] of Object.entries(pending)) {
                    const algoLatency = networkBase + metrics.encrypt + metrics.decrypt;
                    if (!resultsBufferRef.current[algorithm]) resultsBufferRef.current[algorithm] = [];
                    resultsBufferRef.current[algorithm].push({
                      ts: endTs,
                      enc: metrics.encrypt,
                      dec: metrics.decrypt,
                      th: metrics.throughput,
                      latency: algoLatency,
                    });
                    pruneRolling(resultsBufferRef.current[algorithm]);
                    exportSnapshotRef.current[algorithm] = {
                      ts: endTs,
                      ciphertextHex: sliceHex(metrics.ciphertextHex),
                      encrypt: metrics.encrypt,
                      decrypt: metrics.decrypt,
                      throughput: metrics.throughput,
                      latency: algoLatency,
                    };
                    console.log('[BENCHMARK]', algorithm, 'enc=', metrics.encrypt.toFixed(4), 'dec=', metrics.decrypt.toFixed(4), 'lat=', algoLatency.toFixed(4));
                  }
                  benchmarkByFrameRef.current.delete(frameKey);
                }

                chunk.data = meta.media.buffer;
              } else {
                chunk.data = dec.ciphertext.buffer;
              }
            } catch (err) {
              // pass through
            }
            controller.enqueue(chunk);
          }
        });
        cs.readable.pipeThrough(transformer).pipeTo(cs.writable);
      } catch (err) { console.warn('Failed to attach receiver transform', err); }
    }
  }

  // Fallback sampler: if per-sender Insertable Streams weren't attached, sample local video frames
  // and send small downscaled buffers to the benchmark worker while a call is active.
  useEffect(() => {
    let id: number | null = null;
    const SAMPLE_W = 160;
    const SAMPLE_H = 120;

    if (!connectedPeer) {
      return;
    }

    const pc = pcRef.current;
    // attempt to attach transforms first (may set hasTransformAttached flags)
    if (pc) {
      tryAttachTransforms(pc);
    }

    const anyAttached = !!(pc && (
      pc.getSenders().some(s => !!((s as any).hasTransformAttached)) ||
      pc.getReceivers().some(r => !!((r as any).hasTransformAttached))
    ));

    if (anyAttached) {
      console.log('[BENCHMARK] Transforms attached to at least one sender/receiver; fallback sampler not started');
      return;
    }

    console.log('[BENCHMARK] No transforms attached; starting fallback canvas sampler for benchmark (connectedPeer=true)');
    const canvas = document.createElement('canvas');
    canvas.width = SAMPLE_W;
    canvas.height = SAMPLE_H;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    id = window.setInterval(() => {
      try {
        const v = localVideoRef.current;
        if (!v) return;
        ctx.drawImage(v, 0, 0, SAMPLE_W, SAMPLE_H);
        const imageData = ctx.getImageData(0, 0, SAMPLE_W, SAMPLE_H);
        // copy the buffer so it can be transferred
        const buf = imageData.data.buffer.slice(0);
        const captureTs = Date.now();
        const frameId = `${Math.floor(captureTs)}`;
        console.log('[BENCHMARK] Fallback chunk captured', buf.byteLength);
        BenchmarkWorker.postMessage({ type: 'benchmark', data: buf, frameId, captureTs }, [buf]);
        console.log('[BENCHMARK] Chunk sent to worker (fallback)');
      } catch (e) {
        console.log('[BENCHMARK] fallback sample error', e);
      }
    }, 500);

    return () => {
      if (id) window.clearInterval(id);
    };
  }, [connectedPeer]);

  async function handleCreateRoom() {
    console.log('[RealtimeBenchmark] create room click');
    sendSignalingMessage({ type: 'create' });
  }

  async function handleJoinRoom() {
    if (!roomId) return toast.error('Enter room id');
    console.log('[RealtimeBenchmark] join room click', roomId);
    if (!pcRef.current) await createPeerConnection();
    sendSignalingMessage({ type: 'join', roomId });
  }

  const chartData = Object.entries(stats).map(([k, v]) => ({
    algorithm: k,
    encrypt: v.encrypt,
    decrypt: v.decrypt,
    throughput: v.throughput,
    latency: v.latency,
  }));
  console.log("[BENCHMARK] Chart data", chartData);

  // Prepare a table-like dataset for detailed results (keeps fixed algorithm order)
  const algorithmOrder = ['chacha20'];
  const displayNames: Record<string, string> = {
    chacha20: 'ChaCha20',
    mickey: 'Mickey',
    ascon: 'Ascon',
    grain128aead: 'Grain128AEAD',
    trivium: 'Trivium',
  };
  const colorClass: Record<string, string> = {
    chacha20: 'bg-yellow-400',
    mickey: 'bg-purple-500',
    ascon: 'bg-red-500',
    grain128aead: 'bg-green-400',
    trivium: 'bg-blue-400',
  };

  const bestThroughput = algorithmOrder.reduce((best, k) => {
    const v = stats[k];
    if (!v) return best;
    return v.throughput > (best.value ?? 0) ? { key: k, value: v.throughput } : best;
  }, {} as { key?: string; value?: number });

  function fmtNum(n?: number, digits = 3) {
    if (n === undefined || n === null || Number.isNaN(n)) return '-';
    return n.toFixed(digits);
  }

  function formatTimestamp(ts: number): string {
    const d = new Date(ts);
    const pad = (x: number) => x.toString().padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  function downloadCiphertextReport(algoKey: string) {
    const item = exportSnapshotRef.current[algoKey];
    if (!item) {
      toast.error(`Xali video qo'ng'iroq amalga oshirilmadi:  ${displayNames[algoKey] || algoKey} algoritmi uchun`);
      return;
    }
    const content = [
      `Timestamp: ${formatTimestamp(item.ts)}`,
      `Algorithm: ${displayNames[algoKey] || algoKey}`,
      '',
      'Ciphertext:',
      item.ciphertextHex,
      '',
      `Encrypt Time: ${item.encrypt.toFixed(3)} ms`,
      `Decrypt Time: ${item.decrypt.toFixed(3)} ms`,
      `Throughput: ${item.throughput.toFixed(3)} MB/s`,
      `Latency: ${item.latency.toFixed(3)} ms`,
      '',
    ].join('\n');
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${algoKey}-${item.ts}.txt`;
    link.click();
    URL.revokeObjectURL(url);
    console.log('[EXPORT] Generated TXT for', algoKey);
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <div className="card">
          <h2 className="font-bold">Local</h2>
          <video ref={localVideoRef} autoPlay muted playsInline className="w-full h-64 bg-black" />
        </div>
        <div className="card">
          <h2 className="font-bold">Remote</h2>
          <video ref={remoteVideoRef} autoPlay playsInline className="w-full h-64 bg-black" />
        </div>
      </div>

      <div className="card flex items-center gap-3">
        <div className="flex gap-2">
          <button onClick={handleCreateRoom} className="btn-primary">Tarmoq yaratish</button>
<input 
  value={roomId} 
  onChange={e => setRoomId(e.target.value)} 
  placeholder="Room ID" 
  className="input" 
  style={{ color: 'black' }} // Yozuv rangini qora qiladi
/>
          <button onClick={handleJoinRoom} className="btn-secondary">Tarmoqqa kirish</button>
        </div>
        <div className="ml-auto">
          <div>Tarmoq statusi :  <strong style={{ color: wsStatus === 'ULANGAN' ? '#16a34a' : wsStatus === 'ULANMOQDA' ? '#ca8a04' : '#dc2626' }}>{wsStatus}</strong></div>
          <div>Tarmoq nomi: <strong>{currentRoom ?? '-'}</strong></div>
          <div>Ulanish: <strong>{connectedPeer ? 'Ha' : 'Yo\'q'}</strong></div>
          <div>Faol algoritm: <strong>ChaCha20</strong></div>
        </div> 
      </div>

      <div className="grid grid-cols-4 gap-4">
        <div className="card">
          <h3 className="font-semibold">Shifrlash vaqt bo'yicha (ms)</h3>
          <div className="mt-2">
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={chartData.map(x => ({ algorithm: x.algorithm, value: x.encrypt }))}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="algorithm" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#0ea5e9" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h3 className="font-semibold">Deshifrlash vaqt bo'yicha (ms)</h3>
          <div className="mt-2">
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={chartData.map(x => ({ algorithm: x.algorithm, value: x.decrypt }))}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="algorithm" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#10b981" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h3 className="font-semibold">O'tkazuvchanlik (MB/s)</h3>
          <div className="mt-2">
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={chartData.map(x => ({ algorithm: x.algorithm, value: x.throughput }))}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="algorithm" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#f59e0b" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h3 className="font-semibold">Kechikish (ms)</h3>
          <div className="mt-2">
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={chartData.map(x => ({ algorithm: x.algorithm, value: x.latency }))}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="algorithm" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#a855f7" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="card mt-6">
        <h3 className="font-semibold mb-4">Algoritm natijalari</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="text-sm text-slate-300">
                <th className="py-2">Algoritm</th>
                <th className="py-2">Shifrlash vaqti</th>
                <th className="py-2">Deshifrlash vaqti</th>
                <th className="py-2">O'tkazuvchanlik qobiliyati</th>
                <th className="py-2">Kechikish</th>
              </tr>
            </thead>
            <tbody>
              {algorithmOrder.map((k) => {
                const v = stats[k];
                const isBest = bestThroughput.key === k;
                return (
                  <tr key={k} className="border-t border-slate-700">
                    <td className="py-3">
                      <div className="flex items-center gap-3">
                        <span className={`inline-block w-3 h-3 rounded-full ${colorClass[k] || 'bg-gray-400'}`} />
                        <div>
                          <div className="font-medium">{displayNames[k] || k}</div>
                          {isBest && <div className="text-xs text-emerald-400">Eng Tez</div>}
                        </div>
                      </div>
                    </td>
                    <td className="py-3">{v ? `${fmtNum(v.encrypt)} ms` : '-'}</td>
                    <td className="py-3">{v ? `${fmtNum(v.decrypt)} ms` : '-'}</td>
                    <td className="py-3">{v ? `${fmtNum(v.throughput, 4)} MB/s` : '-'}</td>
                    <td className="py-3">{v ? `${fmtNum(v.latency)} ms` : '-'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="card">
          <h3 className="font-semibold">Shifrlash vaqt bo'yicha (ms)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={historyPoints}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="label" />
              <YAxis />
              <Tooltip />
              <Legend />
              {algorithmOrder.map((k) => (
                <Line key={`${k}-enc`} type="monotone" dataKey={`${k}_enc`} name={`${displayNames[k]}`} strokeWidth={2} dot={false} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <h3 className="font-semibold">Deshifrlash vaqt bo'yicha (ms)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={historyPoints}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="label" />
              <YAxis />
              <Tooltip />
              <Legend />
              {algorithmOrder.map((k) => (
                <Line key={`${k}-dec`} type="monotone" dataKey={`${k}_dec`} name={`${displayNames[k]}`} strokeWidth={2} dot={false} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <h3 className="font-semibold">O'tkazuvchanlik vaqt bo'yicha (MB/s)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={historyPoints}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="label" />
              <YAxis />
              <Tooltip />
              <Legend />
              {algorithmOrder.map((k) => (
                <Line key={`${k}-th`} type="monotone" dataKey={`${k}_th`} name={`${displayNames[k]}`} strokeWidth={2} dot={false} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <h3 className="font-semibold">Kechikish vaqt bo'yicha (ms)</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={historyPoints}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="label" />
              <YAxis />
              <Tooltip />
              <Legend />
              {algorithmOrder.map((k) => (
                <Line key={`${k}-lat`} type="monotone" dataKey={`${k}_lat`} name={`${displayNames[k]}`} strokeWidth={2} dot={false} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card">
        <h3 className="font-semibold mb-3">Shifrmatn yuklab olish (TXT)</h3>
        <div className="grid grid-cols-5 gap-2">
          {algorithmOrder.map((k) => (
            <button key={k} className="btn-secondary" onClick={() => downloadCiphertextReport(k)}>
              {displayNames[k]} TXT
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
