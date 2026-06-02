import React, { useEffect, useRef, useState } from 'react';
import { LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, BarChart, Bar } from 'recharts';
import toast from 'react-hot-toast';

// Import ChaCha20 for inline encryption of media frames
import { chaCha20Encrypt, chaCha20Decrypt } from '../algorithms/chacha20';

// Worker (bundled by Vite)
const BenchmarkWorker = new Worker(new URL('../workers/benchmarkWorker.ts', import.meta.url), { type: 'module' });

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
  const [stats, setStats] = useState<Record<string, { encrypt: number; decrypt: number; throughput: number }>>({});

  const resultsBufferRef = useRef<Record<string, Array<{ ts: number; enc: number; dec: number; th: number }>>>({});

  useEffect(() => {
    BenchmarkWorker.onmessage = (ev) => {
      const msg = ev.data;
      if (msg.type !== 'result') return;
      const now = Date.now();
      for (const r of msg.results) {
        if (!resultsBufferRef.current[r.algorithm]) resultsBufferRef.current[r.algorithm] = [];
        resultsBufferRef.current[r.algorithm].push({ ts: now, enc: r.encryptTime, dec: r.decryptTime, th: r.throughput });
      }
    };

    const interval = setInterval(() => {
      const out: Record<string, { encrypt: number; decrypt: number; throughput: number }> = {};
      const cutoff = Date.now() - 1000;
      for (const algo of Object.keys(resultsBufferRef.current)) {
        const arr = resultsBufferRef.current[algo];
        // keep last 5 seconds of results
        while (arr.length && arr[0].ts < cutoff - 4000) arr.shift();
        const recent = arr.filter(x => x.ts >= cutoff);
        if (recent.length === 0) continue;
        const enc = recent.reduce((s, v) => s + v.enc, 0) / recent.length;
        const dec = recent.reduce((s, v) => s + v.dec, 0) / recent.length;
        const th = recent.reduce((s, v) => s + v.th, 0) / recent.length;
        out[algo] = { encrypt: parseFloat(enc.toFixed(3)), decrypt: parseFloat(dec.toFixed(3)), throughput: parseFloat(th.toFixed(3)) };
      }
      setStats(out);
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

  useEffect(() => { startLocalMedia(); }, []);

  function ensureWebSocket() {
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) return wsRef.current;
    const wsUrl = (import.meta.env.VITE_WS_URL as string) ?? 'ws://0.0.0.0:3099/ws';
    const ws = new WebSocket(wsUrl);
    ws.onopen = () => console.info('Signaling connected');
    ws.onmessage = (ev) => handleWsMessage(ev);
    ws.onclose = () => console.info('Signaling closed');
    ws.onerror = (e) => console.warn('WS error', e);
    wsRef.current = ws;
    return ws;
  }

  function handleWsMessage(ev: MessageEvent) {
    const msg = JSON.parse(ev.data);
    switch (msg.type) {
      case 'created':
        setCurrentRoom(msg.roomId);
        setRoomKeyHex(msg.keyHex);
        toast.success(`Room ${msg.roomId} created`);
        break;
      case 'joined':
        setCurrentRoom(msg.roomId);
        setRoomKeyHex(msg.keyHex);
        toast.success(`Joined room ${msg.roomId}`);
        break;
      case 'peer-joined':
        setConnectedPeer(true);
        toast.success('Peer joined');
        // if I'm the creator, start negotiation
        if (pcRef.current && (pcRef.current.signalingState === 'stable' || true)) {
          createAndSendOffer();
        }
        break;
      case 'peer-left':
        setConnectedPeer(false);
        break;
      case 'signal':
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
      ensureWebSocket().send(JSON.stringify({ type: 'signal', roomId: currentRoom, data: { type: 'offer', sdp: offer.sdp } }));
    } catch (err) { console.error(err); }
  }

  async function onReceiveOffer(sdp: string) {
    if (!pcRef.current) await createPeerConnection();
    const pc = pcRef.current!;
    await pc.setRemoteDescription({ type: 'offer', sdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    ensureWebSocket().send(JSON.stringify({ type: 'signal', roomId: currentRoom, data: { type: 'answer', sdp: answer.sdp } }));
  }

  async function onReceiveAnswer(sdp: string) {
    const pc = pcRef.current;
    if (!pc) return;
    await pc.setRemoteDescription({ type: 'answer', sdp });
  }

  async function onReceiveIce(candidate: any) {
    const pc = pcRef.current;
    if (!pc || !candidate) return;
    try { await pc.addIceCandidate(candidate); } catch (err) { console.warn('Invalid ICE candidate', err); }
  }

  async function createPeerConnection() {
    const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
    pcRef.current = pc;

    pc.onicecandidate = (ev) => {
      if (ev.candidate) ensureWebSocket().send(JSON.stringify({ type: 'signal', roomId: currentRoom, data: { type: 'ice', candidate: ev.candidate } }));
    };

    pc.ontrack = (ev) => {
      if (remoteVideoRef.current) remoteVideoRef.current.srcObject = ev.streams[0];
    };

    // Add local tracks
    if (localStreamRef.current) {
      for (const track of localStreamRef.current.getTracks()) {
        const sender = pc.addTrack(track, localStreamRef.current);
      }
    }

    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'connected') setConnectedPeer(true);
      if (pc.connectionState === 'disconnected' || pc.connectionState === 'closed') setConnectedPeer(false);
    };

    // Attach Insertable Streams transforms if available
    setTimeout(() => {
      tryAttachTransforms(pc);
    }, 500);

    return pc;
  }

  function tryAttachTransforms(pc: RTCPeerConnection) {
    const keyHex = roomKeyHex;
    if (!keyHex) return;
    const key = hexToBytes(keyHex);

    // Sender side transform (encrypt before sending)
    const senders = pc.getSenders();
    for (const sender of senders) {
      try {
        const cs = (sender as any).createEncodedStreams?.();
        if (!cs) continue;
        const transformer = new TransformStream({
          transform: (chunk: any, controller: any) => {
            try {
              const data = new Uint8Array(chunk.data);
              // copy for worker
              const copy = data.slice().buffer;
              BenchmarkWorker.postMessage({ type: 'benchmark', data: copy }, [copy]);

              const nonce = makeNonceFromTimestamp(chunk.timestamp ?? Date.now());
              const res = chaCha20Encrypt(data, key, nonce);
              chunk.data = res.ciphertext.buffer;
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
      try {
        const cs = (receiver as any).createEncodedStreams?.();
        if (!cs) continue;
        const transformer = new TransformStream({
          transform: (chunk: any, controller: any) => {
            try {
              const data = new Uint8Array(chunk.data);
              const nonce = makeNonceFromTimestamp(chunk.timestamp ?? Date.now());
              const res = chaCha20Decrypt(data, key, nonce);
              chunk.data = res.ciphertext.buffer;
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

  async function handleCreateRoom() {
    ensureWebSocket();
    wsRef.current!.send(JSON.stringify({ type: 'create' }));
  }

  async function handleJoinRoom() {
    if (!roomId) return toast.error('Enter room id');
    ensureWebSocket();
    wsRef.current!.send(JSON.stringify({ type: 'join', roomId }));
    if (!pcRef.current) await createPeerConnection();
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
          <button onClick={handleCreateRoom} className="btn-primary">Create Room</button>
<input 
  value={roomId} 
  onChange={e => setRoomId(e.target.value)} 
  placeholder="Room ID" 
  className="input" 
  style={{ color: 'black' }} // Yozuv rangini qora qiladi
/>
          <button onClick={handleJoinRoom} className="btn-secondary">Join Room</button>
        </div>
        <div className="ml-auto">
          <div>Current room: <strong>{currentRoom ?? '-'}</strong></div>
          <div>Connected: <strong>{connectedPeer ? 'Yes' : 'No'}</strong></div>
          <div>Active algorithm: <strong>ChaCha20</strong></div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="card">
          <h3 className="font-semibold">Encryption Time (ms)</h3>
          <div className="mt-2">
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={Object.entries(stats).map(([k,v]) => ({ algorithm: k, value: v.encrypt }))}>
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
          <h3 className="font-semibold">Decryption Time (ms)</h3>
          <div className="mt-2">
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={Object.entries(stats).map(([k,v]) => ({ algorithm: k, value: v.decrypt }))}>
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
          <h3 className="font-semibold">Throughput (MB/s)</h3>
          <div className="mt-2">
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={Object.entries(stats).map(([k,v]) => ({ algorithm: k, value: v.throughput }))}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="algorithm" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#f59e0b" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
