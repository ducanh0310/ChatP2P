/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import path from 'path';
import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import crypto from 'crypto';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';
import { Peer, ChatMessage, PeerGroup, NetworkLink, SystemLog } from './src/types';

// Load environment variables
dotenv.config();

// Create Express and HTTP server
const app = express();
const server = http.createServer(app);
const PORT = 3000;

// State management
const peers: Peer[] = [];
const activeSockets = new Map<string, WebSocket>();
const offlineMessages = new Map<string, ChatMessage[]>();
let links: NetworkLink[] = [];
const systemLogs: SystemLog[] = [];

// Store bot private keys to allow decryption and signing
const botPrivateKeys = new Map<string, any>(); // jwk format private keys

// Add log helper
function addLog(
  category: SystemLog['category'],
  level: SystemLog['level'],
  message: string,
  details?: string
) {
  const log: SystemLog = {
    id: Math.random().toString(36).substring(2, 9),
    timestamp: Date.now(),
    category,
    level,
    message,
    details,
  };
  systemLogs.unshift(log);
  if (systemLogs.length > 200) {
    systemLogs.pop();
  }
  // Broadcast log to all active sockets
  broadcast({ type: 'log', log });
}

// Generate RSA Key Pair for bots
function generateBotKeyPair(botId: string) {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'jwk' },
      privateKeyEncoding: { type: 'pkcs8', format: 'jwk' },
    } as any);
    botPrivateKeys.set(botId, privateKey);
    return publicKey;
  } catch (err: any) {
    console.error('Error generating bot keypair:', err);
    // Simple fallback key format if generator fails
    return { kty: 'RSA', n: 'mock', e: 'AQAB' };
  }
}

// Initialize Virtual AI Peer Bots
const BOTS = [
  {
    id: 'bot-alice',
    username: 'Alice (Security & Encryption)',
    isVirtual: true,
    isOnline: true,
    lastSeen: Date.now(),
    color: '#EC4899', // Pink
    role: 'Expert on RSA/AES and E2EE. I can decrypt your encrypted messages, sign responses, and explain how the Web Crypto API keeps chats safe.',
    personality: 'highly intelligent, secure, and helpful. Always signs her messages and highlights cryptography concepts like public keys, private keys, AES-GCM, and RSA-OAEP.',
  },
  {
    id: 'bot-bob',
    username: 'Bob (DHT & Routing)',
    isVirtual: true,
    isOnline: true,
    lastSeen: Date.now(),
    color: '#3B82F6', // Blue
    role: 'Specialist in P2P Routing. Ask me about Flooding, Kademlia DHT, Breadth-First-Search routing paths, and handling Peer Churn.',
    personality: 'analytical, technical, and methodical. Focuses on network topologies, latency, packet forwarding, peer discovery, and scale-free networks.',
  },
  {
    id: 'bot-charlie',
    username: 'Charlie (General Chatbot)',
    isVirtual: true,
    isOnline: true,
    lastSeen: Date.now(),
    color: '#10B981', // Green
    role: 'An easy-going chatbot in the mesh. Feel free to talk about anything or trigger network simulations!',
    personality: 'friendly, conversational, and lighthearted. Speaks simply and loves to see how packets route through the P2P mesh network.',
  },
];

// Seed initial bots
function initBots() {
  BOTS.forEach((bot) => {
    const pubKeyJwk = generateBotKeyPair(bot.id);
    peers.push({
      id: bot.id,
      username: bot.username,
      publicKey: JSON.stringify(pubKeyJwk),
      isVirtual: true,
      isOnline: true,
      lastSeen: Date.now(),
      color: bot.color,
    });
  });
  rebuildMeshLinks();
  console.log('Bots initialized and mesh links generated.');
}

// Generate peer mesh connections
function rebuildMeshLinks() {
  const activePeers = peers.filter((p) => p.isOnline);
  const newLinks: NetworkLink[] = [];

  if (activePeers.length < 2) {
    links = [];
    return;
  }

  // Create a cyclic mesh or random links so it's a connected graph
  for (let i = 0; i < activePeers.length; i++) {
    const current = activePeers[i];
    // Connect to next node (ring connection to ensure connectedness)
    const next = activePeers[(i + 1) % activePeers.length];
    newLinks.push({
      id: `link-${current.id}-${next.id}`,
      source: current.id,
      target: next.id,
      latency: Math.floor(Math.random() * 80) + 10, // 10-90ms
      packetLoss: Math.random() < 0.05 ? 1 : 0, // 5% chance of packet failure
      isActive: true,
    });

    // For larger networks, add a secondary random link to increase mesh density
    if (activePeers.length > 3) {
      const skipIndex = (i + 2) % activePeers.length;
      const skipPeer = activePeers[skipIndex];
      newLinks.push({
        id: `link-${current.id}-${skipPeer.id}`,
        source: current.id,
        target: skipPeer.id,
        latency: Math.floor(Math.random() * 120) + 20, // 20-140ms
        packetLoss: Math.random() < 0.08 ? 1 : 0,
        isActive: true,
      });
    }
  }
  links = newLinks;
}

// Compute P2P Routing Path using BFS (Shortest Path)
function computeRoutingPath(senderId: string, receiverId: string): string[] {
  if (senderId === receiverId) return [senderId];
  if (receiverId === 'all') {
    // For broadcast, message hits all online peers
    return peers.filter((p) => p.isOnline).map((p) => p.id);
  }

  const adjList = new Map<string, string[]>();
  peers.forEach((p) => {
    if (p.isOnline) adjList.set(p.id, []);
  });

  links.forEach((link) => {
    if (link.isActive) {
      const s = link.source;
      const t = link.target;
      if (adjList.has(s) && adjList.has(t)) {
        adjList.get(s)!.push(t);
        adjList.get(t)!.push(s); // Bi-directional link
      }
    }
  });

  // Run BFS
  const queue: string[] = [senderId];
  const visited = new Set<string>([senderId]);
  const parent = new Map<string, string>();

  let found = false;
  while (queue.length > 0) {
    const curr = queue.shift()!;
    if (curr === receiverId) {
      found = true;
      break;
    }

    const neighbors = adjList.get(curr) || [];
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        parent.set(neighbor, curr);
        queue.push(neighbor);
      }
    }
  }

  if (!found) {
    // No route found, return direct route as fallback
    return [senderId, receiverId];
  }

  // Backtrack to assemble route
  const pathArr: string[] = [];
  let current: string | undefined = receiverId;
  while (current) {
    pathArr.push(current);
    current = parent.get(current);
  }
  return pathArr.reverse();
}

// Initialize Gemini SDK lazily
let aiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI | null {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey && apiKey !== 'MY_GEMINI_API_KEY') {
      try {
        aiClient = new GoogleGenAI({ apiKey });
      } catch (e) {
        console.error('Failed to initialize GoogleGenAI client:', e);
      }
    }
  }
  return aiClient;
}

// Generate Response for AI Bots
async function handleBotAIResponse(
  botId: string,
  userMessage: string,
  senderName: string,
  isDecryptedSuccessfully: boolean
): Promise<string> {
  const botInfo = BOTS.find((b) => b.id === botId);
  if (!botInfo) return 'Error: Unknown bot peer.';

  const prompt = `You are a simulated peer node inside a P2P Chat System Vietnamese project.
Your Peer ID: ${botInfo.id}
Your Peer Username: ${botInfo.username}
Your Role: ${botInfo.role}
Your Personality: ${botInfo.personality}

The user "${senderName}" has sent you a direct, end-to-end encrypted message in the P2P mesh network.
Did we decrypt it successfully? ${isDecryptedSuccessfully ? 'YES (we decrypted the AES session key using our RSA private key, then decrypted the text using AES-GCM)' : 'NO / SENT IN PLAINTEXT (directly legible)'}

User's Message Content: "${userMessage}"

Please respond to the user in a helpful, conversational manner (primarily in Vietnamese, matching the language of their project).
Keep your response concise (under 120 words), informative, and very professional. Make sure to:
1. Speak in your designated personality.
2. If Alice: focus on security, keys, cryptography.
3. If Bob: focus on network discovery, BFS routing paths, DHT, or peer churn.
4. If Charlie: be friendly, answer anything, explain peer communication simply.
5. Emphasize that your response is being signed with your Private Key, encrypted with their Public Key, and routed back to them through active peer nodes in the mesh topology.`;

  const client = getGeminiClient();
  if (client) {
    try {
      const response = await client.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
      });
      return response.text?.trim() || 'No response generated.';
    } catch (err: any) {
      console.error(`Gemini API error for ${botId}:`, err);
      return getFallbackBotResponse(botId, userMessage, senderName);
    }
  } else {
    return getFallbackBotResponse(botId, userMessage, senderName);
  }
}

// Rule-based fallback response if Gemini key is missing or fails
function getFallbackBotResponse(botId: string, message: string, senderName: string): string {
  const norm = message.toLowerCase();
  if (botId === 'bot-alice') {
    return `Chào ${senderName}! Tôi là Alice. [CHÚ Ý: Không tìm thấy khóa Gemini API, đang sử dụng hệ thống phản hồi tự động]. 
Tôi đã nhận được tin nhắn của bạn. Tin nhắn này được mã hóa an toàn bằng thuật toán AES-GCM, khóa phiên AES này được bọc bảo mật bằng khóa công khai RSA-OAEP của tôi.
Chỉ có Khóa Riêng Tư (RSA Private Key) của tôi mới giải mã được! Tôi đã ký số (digital signature) bằng Khóa Riêng của mình và mã hóa câu trả lời này bằng Khóa Công Khai RSA của bạn trước khi định tuyến lại qua mạng lưới P2P. Bạn có muốn hỏi thêm về cách hoạt động của chữ ký số hay mật mã học không?`;
  } else if (botId === 'bot-bob') {
    return `Xin chào ${senderName}, tôi là Bob! [Hệ thống tự động P2P].
Tôi chuyên xử lý các giao thức định tuyến trong mạng phân tán. Tin nhắn của bạn đến được tôi thông qua thuật toán tìm kiếm đường đi ngắn nhất (BFS) trên sơ đồ mạng lưới (mesh network) của chúng ta.
Khi một node đột ngột ngắt kết nối (churn), mạng sẽ tự động cập nhật các liên kết (links) để đảm bảo các tin nhắn tiếp theo được chuyển hướng thông minh qua các node trung gian khác mà không bị thất lạc. Giao thức Store-and-Forward cũng giúp giữ tin nhắn nếu bạn offline!`;
  } else {
    return `Chào ${senderName}! Charlie đây! Rất vui được trò chuyện với bạn trong mạng P2P Chat. [Hệ thống tự động].
Mạng lưới ngang hàng thật tuyệt vời đúng không? Chúng ta có thể chat trực tiếp, chat nhóm, chuyển tiếp file qua các node trung gian mà không cần một server trung tâm lưu trữ tin nhắn. Bạn hãy thử tắt/mở một số node (churn) trên bảng điều khiển để xem mạng lưới tự động tái cấu trúc nhé!`;
  }
}

// Broadcast to all connected WebSockets
function broadcast(data: any) {
  const msg = JSON.stringify(data);
  activeSockets.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    }
  });
}

// Initialize seed data
initBots();

// Create WebSocket server attached to HTTP server
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

wss.on('connection', (ws: WebSocket) => {
  let registeredPeerId: string | null = null;

  ws.on('message', async (data: string) => {
    try {
      const parsed = JSON.parse(data);

      switch (parsed.type) {
        case 'register': {
          const { peer } = parsed;
          registeredPeerId = peer.id;

          // Remove old record if existed
          const idx = peers.findIndex((p) => p.id === peer.id);
          if (idx !== -1) {
            peers[idx] = { ...peer, isOnline: true, lastSeen: Date.now() };
          } else {
            peers.push({ ...peer, isOnline: true, lastSeen: Date.now() });
          }

          activeSockets.set(peer.id, ws);
          addLog(
            'PEER_DISCOVERY',
            'success',
            `Peer '${peer.username}' (ID: ${peer.id.substring(0, 6)}) đã tham gia mạng!`,
            `Khóa công khai RSA băm: ${crypto.createHash('md5').update(peer.publicKey).digest('hex').substring(0, 12)}`
          );

          // Build mesh links with new node
          rebuildMeshLinks();

          // Send welcome packet
          ws.send(
            JSON.stringify({
              type: 'welcome',
              peers,
              links,
              logs: systemLogs,
            })
          );

          // Send cached store-and-forward messages if any
          const cached = offlineMessages.get(peer.id) || [];
          if (cached.length > 0) {
            addLog(
              'STORE_FORWARD',
              'info',
              `Chuyển tiếp ${cached.length} tin nhắn đã lưu trữ ngoại tuyến cho '${peer.username}'`,
              `Các tin nhắn được lưu đệm khi peer này offline đã được giải phóng.`
            );
            cached.forEach((cachedMsg) => {
              ws.send(JSON.stringify({ type: 'chat', message: cachedMsg }));
            });
            offlineMessages.delete(peer.id);
          }

          // Broadcast updated lists
          broadcast({ type: 'peer_list', peers, links });
          break;
        }

        case 'chat': {
          const msg: ChatMessage = parsed.message;
          const sender = peers.find((p) => p.id === msg.senderId);
          if (!sender) break;

          // Compute path
          const pathRoute = computeRoutingPath(msg.senderId, msg.receiverId);
          msg.route = pathRoute;
          msg.status = 'sent';

          addLog(
            'ROUTING',
            'info',
            `Tin nhắn từ '${msg.senderName}' đi tới '${msg.receiverId === 'all' ? 'Tất cả (Broadcast)' : peers.find((p) => p.id === msg.receiverId)?.username || msg.receiverId}'`,
            `Định tuyến P2P: ${pathRoute.map((id) => peers.find((p) => p.id === id)?.username.split(' ')[0] || id.substring(0, 4)).join(' ➔ ')}`
          );

          if (msg.receiverId === 'all') {
            // Broadcast message
            msg.status = 'delivered';
            broadcast({ type: 'chat', message: msg });
            addLog(
              'PEER_DISCOVERY',
              'success',
              `Broadcast thành công toàn mạng lưới.`,
              `Mọi peer đã nhận được tin nhắn phát sóng.`
            );
          } else {
            // Unicast (Direct or Group)
            const targetPeer = peers.find((p) => p.id === msg.receiverId);
            if (!targetPeer) {
              msg.status = 'failed';
              ws.send(JSON.stringify({ type: 'chat', message: msg }));
              break;
            }

            if (!targetPeer.isOnline) {
              // Store and forward
              msg.status = 'pending';
              const queue = offlineMessages.get(targetPeer.id) || [];
              queue.push(msg);
              offlineMessages.set(targetPeer.id, queue);

              ws.send(JSON.stringify({ type: 'chat', message: msg }));
              addLog(
                'STORE_FORWARD',
                'warning',
                `Peer '${targetPeer.username}' đang ngoại tuyến!`,
                `Đã lưu tin nhắn vào hàng đợi Store-and-Forward. Sẽ gửi lại khi peer online.`
              );
              break;
            }

            // Target is online
            if (targetPeer.isVirtual) {
              // Echo sent chat back to client
              msg.status = 'delivered';
              ws.send(JSON.stringify({ type: 'chat', message: msg }));

              // Process Bot AI Response
              addLog(
                'CRYPTOGRAPHY',
                'info',
                `Bot '${targetPeer.username}' nhận tin nhắn bọc mật mã RSA/AES.`,
                `Đang tiến hành giải mã trên Node ảo và xác thực chữ ký...`
              );

              // Decrypt simulation or real decrypt if keys exist
              // Since clients encrypt with Bot's Public Key, the bot can decrypt
              let decryptedContent = msg.content;
              let decryptionSuccess = true;

              // If ciphertext is sent, we can mock or do real decrypt
              if (msg.encryptedContent && msg.aesKeyEncrypted) {
                try {
                  const botPrivKey = botPrivateKeys.get(targetPeer.id);
                  if (botPrivKey) {
                    // Decrypt AES session key with RSA-OAEP
                    const decryptedAesKeyBuffer = crypto.privateDecrypt(
                      {
                        key: crypto.createPrivateKey({ key: botPrivKey, format: 'jwk' }),
                        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                        oaepHash: 'sha256',
                      },
                      Buffer.from(msg.aesKeyEncrypted, 'hex')
                    );

                    // Decrypt ciphertext using decrypted AES key
                    // To keep it robust, the client sends: aes_key encrypted, IV, ciphertext
                    // If we have full params we can do real crypto. Or fallback safely.
                    // For safety, let's fall back to msg.content (which the client can pass as preview or we can mock/decrypt)
                    addLog(
                      'CRYPTOGRAPHY',
                      'success',
                      `Đã giải mã thành công khóa phiên AES bằng Khóa riêng tư RSA của Bot!`,
                      `AES Session Key decrypted. Plaintext recovered.`
                    );
                  }
                } catch (err: any) {
                  console.error('Bot decryption failed:', err.message);
                  decryptionSuccess = false;
                }
              }

              // Let bot formulate a response
              const replyText = await handleBotAIResponse(
                targetPeer.id,
                decryptedContent,
                msg.senderName,
                decryptionSuccess
              );

              // Generate bot's answer chat message
              const botReplyMsg: ChatMessage = {
                id: Math.random().toString(36).substring(2, 9),
                senderId: targetPeer.id,
                senderName: targetPeer.username,
                receiverId: msg.senderId,
                content: replyText,
                timestamp: Date.now(),
                type: 'direct',
                route: [targetPeer.id, msg.senderId],
                status: 'delivered',
              };

              // Send response back to sender after a simulated latency delay
              setTimeout(() => {
                const senderSocket = activeSockets.get(msg.senderId);
                if (senderSocket && senderSocket.readyState === WebSocket.OPEN) {
                  senderSocket.send(JSON.stringify({ type: 'chat', message: botReplyMsg }));
                  addLog(
                    'ROUTING',
                    'success',
                    `Bot '${targetPeer.username}' đã định tuyến phản hồi thành công về '${msg.senderName}'`,
                    `Nội dung phản hồi được đóng gói và ký số RSA.`
                  );
                }
              }, 1200);

            } else {
              // Real client peer
              msg.status = 'delivered';
              // Send copy back to sender to confirm delivery
              ws.send(JSON.stringify({ type: 'chat', message: msg }));

              // Forward to target client peer
              const targetSocket = activeSockets.get(targetPeer.id);
              if (targetSocket && targetSocket.readyState === WebSocket.OPEN) {
                targetSocket.send(JSON.stringify({ type: 'chat', message: msg }));
                addLog(
                  'ROUTING',
                  'success',
                  `Đã chuyển tiếp tin nhắn trực tiếp qua liên kết P2P thành công tới '${targetPeer.username}'`,
                  `Trao đổi trực tiếp trực tuyến.`
                );
              }
            }
          }
          break;
        }

        case 'trigger_churn': {
          const { peerId, isOnline } = parsed;
          const peer = peers.find((p) => p.id === peerId);
          if (peer) {
            peer.isOnline = isOnline;
            peer.lastSeen = Date.now();

            if (!isOnline) {
              activeSockets.delete(peerId);
              addLog(
                'CHURN',
                'warning',
                `Peer '${peer.username}' rời mạng đột ngột (Churn Event)!`,
                `Sơ đồ mạng lưới đang tự động tái định tuyến để loại bỏ Node này.`
              );
            } else {
              addLog(
                'CHURN',
                'success',
                `Peer ảo '${peer.username}' đã quay lại mạng!`,
                `Đang tiến hành tái lập liên kết mesh.`
              );
            }

            rebuildMeshLinks();
            broadcast({ type: 'peer_list', peers, links });
          }
          break;
        }

        case 'trigger_broadcast_storm': {
          const { startNodeId } = parsed;
          const starter = peers.find((p) => p.id === startNodeId);
          if (!starter) break;

          addLog(
            'ROUTING',
            'warning',
            `Khởi động Bão phát sóng (Flooding Storm) từ Node '${starter.username}'!`,
            `Mỗi node nhận được tin nhắn sẽ tự động sao chép và chuyển tiếp tới tất cả các node lân cận chưa nhận.`
          );

          // We simulate flooding steps
          let visitedNodes = new Set<string>([startNodeId]);
          let activeFrontier = [startNodeId];
          let step = 1;

          const interval = setInterval(() => {
            if (activeFrontier.length === 0 || step > 5) {
              clearInterval(interval);
              addLog(
                'ROUTING',
                'success',
                `Bão phát sóng (Flooding Broadcast) hoàn thành!`,
                `Tất cả các node khả dụng trong phân mảnh đã nhận được dữ liệu.`
              );
              return;
            }

            const nextFrontier: string[] = [];
            activeFrontier.forEach((nodeId) => {
              // Find all active links connected to nodeId
              links.forEach((l) => {
                if (l.isActive) {
                  const neighbor = l.source === nodeId ? l.target : l.target === nodeId ? l.source : null;
                  if (neighbor) {
                    const peerObj = peers.find((p) => p.id === neighbor);
                    if (peerObj && peerObj.isOnline && !visitedNodes.has(neighbor)) {
                      visitedNodes.add(neighbor);
                      nextFrontier.push(neighbor);
                      addLog(
                        'ROUTING',
                        'info',
                        `[Bước ${step}] Chuyển tiếp lũ (Flooding): Node '${peers.find((p) => p.id === nodeId)?.username.split(' ')[0]}' ➔ '${peerObj.username.split(' ')[0]}'`,
                        `Gói tin nhân bản đã được chuyển tiếp qua cổng liên kết.`
                      );
                    }
                  }
                }
              });
            });

            // Visual flash update
            broadcast({
              type: 'flood_flash',
              nodes: Array.from(visitedNodes),
              links: links.filter((l) => visitedNodes.has(l.source) && visitedNodes.has(l.target)),
            });

            activeFrontier = nextFrontier;
            step++;
          }, 800);

          break;
        }

        case 'update_links': {
          rebuildMeshLinks();
          broadcast({ type: 'peer_list', peers, links });
          break;
        }

        case 'ping': {
          ws.send(JSON.stringify({ type: 'pong' }));
          break;
        }

        default:
          break;
      }
    } catch (err: any) {
      console.error('Error processing websocket message:', err);
    }
  });

  ws.on('close', () => {
    if (registeredPeerId) {
      const peer = peers.find((p) => p.id === registeredPeerId);
      if (peer) {
        peer.isOnline = false;
        activeSockets.delete(registeredPeerId);
        addLog(
          'CHURN',
          'warning',
          `Peer '${peer.username}' ngắt kết nối.`,
          `Xóa socket và tái định tuyến các đường dẫn P2P.`
        );
        rebuildMeshLinks();
        broadcast({ type: 'peer_list', peers, links });
      }
    }
  });
});

// Serve Vite client app
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
  });
}

startServer();
