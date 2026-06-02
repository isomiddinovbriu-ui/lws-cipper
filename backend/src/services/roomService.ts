import crypto from 'crypto';

export interface RoomParticipant {
  id: string;
  ws: any;
}

export interface Room {
  id: string;
  keyHex: string;
  participants: Map<string, RoomParticipant>;
  createdAt: number;
}

const rooms: Map<string, Room> = new Map();

function genRoomId(len = 6) {
  // generate readable room id (alphanumeric uppercase)
  const b = crypto.randomBytes(len);
  let s = '';
  for (let i = 0; i < b.length; i++) s += ((b[i] % 36).toString(36));
  return s.toUpperCase().slice(0, len);
}

function genKeyHex() {
  return crypto.randomBytes(32).toString('hex'); // 256-bit key hex
}

export function createRoom(hostId: string, ws: any): Room {
  let id = genRoomId();
  // ensure unique
  while (rooms.has(id)) id = genRoomId();

  const keyHex = genKeyHex();
  const room: Room = {
    id,
    keyHex,
    participants: new Map(),
    createdAt: Date.now(),
  };

  room.participants.set(hostId, { id: hostId, ws });
  rooms.set(id, room);
  return room;
}

export function joinRoom(roomId: string, clientId: string, ws: any): Room {
  const room = rooms.get(roomId);
  if (!room) throw new Error('Room not found');
  if (room.participants.size >= 2) throw new Error('Tarmoq to‘la'); // "Room is full" in Uzbek
  if (room.participants.has(clientId)) throw new Error('Siz allaqachon tarmoqqa ulandingiz'); // "You are already in the room" in Uzbek
  room.participants.set(clientId, { id: clientId, ws });
  return room;
}

export function leaveRoom(roomId: string, clientId: string) {
  const room = rooms.get(roomId);
  if (!room) return;
  room.participants.delete(clientId);
  if (room.participants.size === 0) rooms.delete(roomId);
}

export function getRoom(roomId: string): Room | undefined {
  return rooms.get(roomId);
}

export function getOtherParticipant(roomId: string, clientId: string): RoomParticipant | undefined {
  const room = rooms.get(roomId);
  if (!room) return undefined;
  for (const [id, p] of room.participants) {
    if (id !== clientId) return p;
  }
  return undefined;
}

export function getParticipants(roomId: string): string[] {
  const room = rooms.get(roomId);
  if (!room) return [];
  return Array.from(room.participants.keys());
}
