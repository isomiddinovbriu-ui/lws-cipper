import http from 'http';
import WebSocket from 'ws';
import { v4 as uuidv4 } from 'uuid';
import { createRoom, joinRoom, leaveRoom, getOtherParticipant, getRoom } from './services/roomService';
import { logger } from './utils/logger';

export function initSignaling(server: http.Server) {
  const wss = new WebSocket.Server({ server, path: '/ws' });

  wss.on('connection', (ws: WebSocket) => {
    const clientId = uuidv4();
    (ws as any).clientId = clientId;
    logger.info(`WS connected: ${clientId}`);

    ws.send(JSON.stringify({ type: 'connected', clientId }));

    ws.on('message', (message: WebSocket.RawData) => {
      try {
        const msg = JSON.parse(message.toString());
        handleMessage(ws, clientId, msg);
      } catch (err) {
        logger.warn('Invalid WS message', (err as Error).message);
      }
    });

    ws.on('close', () => {
      const roomId = (ws as any).roomId as string | undefined;
      if (roomId) {
        leaveRoom(roomId, clientId);
        const other = getOtherParticipant(roomId, clientId);
        if (other) {
          try { other.ws.send(JSON.stringify({ type: 'peer-left', peerId: clientId })); } catch {}
        }
      }
      logger.info(`WS disconnected: ${clientId}`);
    });
  });

  function handleMessage(ws: WebSocket, clientId: string, msg: any) {
    const type = msg.type;
    switch (type) {
      case 'create': {
        const room = createRoom(clientId, ws);
        (ws as any).roomId = room.id;
        ws.send(JSON.stringify({ type: 'created', roomId: room.id, keyHex: room.keyHex, clientId }));
        logger.info(`Room created ${room.id} by ${clientId}`);
        break;
      }

      case 'join': {
        const { roomId } = msg;
        try {
          const room = joinRoom(roomId, clientId, ws);
          (ws as any).roomId = roomId;
          // notify joiner
          ws.send(JSON.stringify({ type: 'joined', roomId, keyHex: room.keyHex, clientId }));
          // notify existing participant
          const other = getOtherParticipant(roomId, clientId);
          if (other) {
            other.ws.send(JSON.stringify({ type: 'peer-joined', peerId: clientId }));
          }
          logger.info(`${clientId} joined room ${roomId}`);
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: (err as Error).message }));
        }
        break;
      }

      case 'leave': {
        const roomId = (ws as any).roomId as string | undefined;
        if (roomId) {
          leaveRoom(roomId, clientId);
          const other = getOtherParticipant(roomId, clientId);
          if (other) other.ws.send(JSON.stringify({ type: 'peer-left', peerId: clientId }));
          (ws as any).roomId = undefined;
        }
        break;
      }

      case 'signal': {
        const { roomId, data } = msg;
        const other = getOtherParticipant(roomId, clientId);
        if (!other) {
          ws.send(JSON.stringify({ type: 'error', message: 'Peer not found' }));
          return;
        }
        try {
          other.ws.send(JSON.stringify({ type: 'signal', from: clientId, data }));
        } catch (err) {
          logger.warn('Failed to forward signal', (err as Error).message);
        }
        break;
      }

      case 'ping': {
        ws.send(JSON.stringify({ type: 'pong' }));
        break;
      }

      default:
        ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type' }));
    }
  }

  logger.info('WebSocket signaling server initialized at /ws');
  return wss;
}
