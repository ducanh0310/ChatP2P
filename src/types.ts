/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface Peer {
  id: string;
  username: string;
  publicKey: string; // PEM-like or raw public key string for RSA-OAEP
  isVirtual: boolean;
  isOnline: boolean;
  lastSeen: number;
  color: string; // Accent color for visual network graph
  x?: number; // Position X on visual mesh canvas
  y?: number; // Position Y on visual mesh canvas
}

export interface ChatMessage {
  id: string;
  senderId: string;
  senderName: string;
  receiverId: string; // Peer ID, Group ID, or 'all' for broadcast
  content: string; // Plaintext (decrypted) content in memory
  encryptedContent?: string; // Hex-encoded ciphertext when sent over network
  aesKeyEncrypted?: string; // Hex-encoded AES key encrypted with receiver's RSA Public Key
  ivHex?: string; // Hex-encoded initialization vector for AES-GCM
  timestamp: number;
  type: 'direct' | 'group' | 'broadcast';
  signature?: string; // Digital signature using sender's RSA Private Key
  route: string[]; // List of Peer IDs this message traversed (routing path)
  status: 'pending' | 'sent' | 'delivered' | 'read' | 'failed';
  groupId?: string;
  fileName?: string;
  fileSize?: number;
  fileData?: string; // Base64 chunk or string data if it's a file
}

export interface PeerGroup {
  id: string;
  name: string;
  members: string[]; // Array of Peer IDs
  createdTime: number;
}

export interface NetworkLink {
  id: string;
  source: string; // Peer ID
  target: string; // Peer ID
  latency: number; // Simulated latency in ms
  packetLoss: number; // Simulated packet loss %
  isActive: boolean;
}

export interface SystemLog {
  id: string;
  timestamp: number;
  category: 'PEER_DISCOVERY' | 'ROUTING' | 'CRYPTOGRAPHY' | 'STORE_FORWARD' | 'CHURN' | 'SYSTEM';
  level: 'info' | 'success' | 'warning' | 'error';
  message: string;
  details?: string;
}

export interface FilePayload {
  id: string;
  name: string;
  size: number;
  type: string;
  senderId: string;
  receiverId: string;
  data: string; // Base64 encrypted data chunk
}
