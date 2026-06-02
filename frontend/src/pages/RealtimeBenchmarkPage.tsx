import React, { useEffect, useRef, useState } from 'react';
import { LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, BarChart, Bar } from 'recharts';
import toast from 'react-hot-toast';

// Import ChaCha20 for inline encryption of media frames
import { chaCha20Encrypt, chaCha20Decrypt } from '../algorithms/chacha20';

// Worker (bundled by Vite)
const BenchmarkWorker = new Worker(new URL('../workers/benchmarkWorker.ts', import.meta.url), { type: 'module' });

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
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      console.debug('[ensureWebSocket] returning existing socket, readyState=', wsRef.current.readyState);
      return wsRef.current;
    }

    const envUrl = (import.meta.env.VITE_WS_URL as string) ?? '';
    const defaultHost = window.location.host;
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = envUrl || `${scheme}://${defaultHost}/ws`;
    debugLog('ensureWebSocket - creating WebSocket to', wsUrl);
    const ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';

    ws.addEventListener('open', () => {
      debugLog('WS open');
    });

    ws.addEventListener('message', (ev) => {
      try {
        debugLog('WS receive raw', ev.data);
        handleWsMessage(ev as MessageEvent);
      } catch (err) {
        debugLog('WS message handler error', err);
      }
    });

    ws.addEventListener('close', (ev) => {
      debugLog('WS close', ev);
      wsRef.current = null;
      toast.error('Signaling connection closed');
    });

    ws.addEventListener('error', (ev) => {
      debugLog('WS error', ev);
      toast.error('Signaling connection error');
    });

    wsRef.current = ws;
    return ws;
  }

  function sendSignalingMessage(obj: unknown) {
    try {
      const ws = ensureWebSocket();
      if (!ws) throw new Error('no websocket');
      const state = ws.readyState;
      debugLog('sendSignalingMessage state=', state, 'msg=', obj);
      const payload = JSON.stringify(obj);
      if (state === WebSocket.OPEN) {
        ws.send(payload);
        debugLog('WS send', payload);
        return true;
      }

      if (state === WebSocket.CONNECTING) {
        debugLog('WS connecting - will send on open');
        const onOpen = () => {
          try { ws.send(payload); debugLog('WS send on open', payload); } catch (e) { debugLog('send on open failed', e); }
          ws.removeEventListener('open', onOpen);
        };
        ws.addEventListener('open', onOpen);
        // set fallback timeout
        setTimeout(() => {
          if (ws.readyState !== WebSocket.OPEN) {
            debugLog('WS did not open in time for message', obj);
            toast.error('Signaling not ready');
          }
        }, 5000);
        return true;
      }

      debugLog('WS not open/connecting - state=', state);
      toast.error('Signaling connection not open');
      return false;
    } catch (err) {
      debugLog('sendSignalingMessage error', err);
      toast.error('Failed to send signaling message');
      return false;
    }
  }

  async function ensureWebSocketOpen(timeout = 5000): Promise<WebSocket> {
    const ws = ensureWebSocket();
    if (!ws) throw new Error('Failed to create WebSocket');
    if (ws.readyState === WebSocket.OPEN) {
      console.debug('[ensureWebSocketOpen] already OPEN');
      return ws;
    }

    if (ws.readyState === WebSocket.CONNECTING) {
      console.debug('[ensureWebSocketOpen] waiting for CONNECTING -> OPEN');
      return await new Promise((resolve, reject) => {
        const onOpen = () => {
          cleanup();
          console.debug('[ensureWebSocketOpen] open event fired');
          resolve(ws);
        };
        const onError = (e: Event) => {
          cleanup();
          console.warn('[ensureWebSocketOpen] error while connecting', e);
          reject(new Error('WebSocket error'));
        };
        const onClose = () => {
          cleanup();
          reject(new Error('WebSocket closed before open'));
        };
        const to = setTimeout(() => {
          cleanup();
          reject(new Error('WebSocket open timeout'));
        }, timeout);

        function cleanup() {
          ws.removeEventListener('open', onOpen as EventListener);
          ws.removeEventListener('error', onError as EventListener);
          ws.removeEventListener('close', onClose as EventListener);
          clearTimeout(to);
        }

        ws.addEventListener('open', onOpen as EventListener);
        ws.addEventListener('error', onError as EventListener);
        ws.addEventListener('close', onClose as EventListener);
      });
    }

    // otherwise (CLOSED or CLOSING), create a fresh one and wait
    console.debug('[ensureWebSocketOpen] socket not open, creating new');
    const newWs = ensureWebSocket();
    return await new Promise((resolve, reject) => {
      const to = setTimeout(() => reject(new Error('WebSocket open timeout')), timeout);
      newWs.addEventListener('open', () => { clearTimeout(to); resolve(newWs); }, { once: true });
      newWs.addEventListener('error', (e) => { clearTimeout(to); reject(new Error('WebSocket error')); }, { once: true });
    });
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
      debugLog('createAndSendOffer - sending offer');
      sendSignalingMessage({ type: 'signal', roomId: currentRoom, data: { type: 'offer', sdp: offer.sdp } });
    } catch (err) { console.error(err); }
  }

  async function onReceiveOffer(sdp: string) {
    if (!pcRef.current) await createPeerConnection();
    const pc = pcRef.current!;
    await pc.setRemoteDescription({ type: 'offer', sdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    debugLog('onReceiveOffer - sending answer');
    sendSignalingMessage({ type: 'signal', roomId: currentRoom, data: { type: 'answer', sdp: answer.sdp } });
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
      if (ev.candidate) {
        debugLog('onicecandidate - sending', ev.candidate);
        sendSignalingMessage({ type: 'signal', roomId: currentRoom, data: { type: 'ice', candidate: ev.candidate } });
      }
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
    debugLog('handleCreateRoom click');
    sendSignalingMessage({ type: 'create' });
  }

  async function handleJoinRoom() {
    if (!roomId) return toast.error('Enter room id');
    debugLog('handleJoinRoom click, roomId=', roomId);
    if (!pcRef.current) await createPeerConnection();
    sendSignalingMessage({ type: 'join', roomId });
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
