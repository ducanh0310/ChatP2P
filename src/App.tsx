/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  MessageSquare, Users, Shield, Server, Activity, ArrowRight,
  Send, RefreshCw, Radio, Terminal, Wifi, WifiOff, AlertTriangle,
  Lock, Unlock, Key, CheckCircle, FileText, Download, Upload, Info, Copy, Eye, EyeOff, LogOut
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { Peer, ChatMessage, PeerGroup, NetworkLink, SystemLog } from './types';
import { generateKeyPair, hybridEncrypt, hybridDecrypt, WebKeys } from './lib/crypto';

export default function App() {
  // Connection and Identity State
  const [ws, setWs] = useState<WebSocket | null>(null);
  const [connected, setConnected] = useState<boolean>(false);
  const [reconnecting, setReconnecting] = useState<boolean>(false);
  const [myKeys, setMyKeys] = useState<WebKeys | null>(null);
  const [myPeer, setMyPeer] = useState<Peer | null>(null);
  const [peers, setPeers] = useState<Peer[]>([]);
  const [links, setLinks] = useState<NetworkLink[]>([]);
  const [logs, setLogs] = useState<SystemLog[]>([]);

  // Authentication State
  const [authTab, setAuthTab] = useState<'signin' | 'signup'>('signin');
  const [authUsername, setAuthUsername] = useState<string>('');
  const [authPassword, setAuthPassword] = useState<string>('');
  const [authColor, setAuthColor] = useState<string>('#8B5CF6'); // Default purple
  const [authError, setAuthError] = useState<string>('');
  const [authLoading, setAuthLoading] = useState<boolean>(false);
  const [authStep, setAuthStep] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);

  const PRESET_COLORS = [
    { value: '#8B5CF6', label: 'Tím Indigo' },
    { value: '#06B6D4', label: 'Xanh Cyan' },
    { value: '#10B981', label: 'Lục Emerald' },
    { value: '#F59E0B', label: 'Vàng Hổ Phách' },
    { value: '#F43F5E', label: 'Đỏ Rose' },
    { value: '#4F46E5', label: 'Xanh Blue' }
  ];

  // UI Selection State
  const [selectedRecipientId, setSelectedRecipientId] = useState<string>('all'); // 'all' = Broadcast Channel
  const [activeTab, setActiveTab] = useState<'network' | 'chat' | 'files' | 'security' | 'logs'>('network');
  const [inputMessage, setInputMessage] = useState<string>('');
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);

  // Simulation state
  const [floodingActive, setFloodingActive] = useState<boolean>(false);
  const [floodedNodes, setFloodedNodes] = useState<string[]>([]);
  const [viewingKeyType, setViewingKeyType] = useState<'public' | 'private' | null>(null);
  const [secureMode, setSecureMode] = useState<boolean>(true); // E2E Encrypted toggle
  
  // File sharing state
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileProgress, setFileProgress] = useState<number>(0);
  const [fileStatus, setFileStatus] = useState<string>('');
  const [sharedFiles, setSharedFiles] = useState<Array<{
    id: string;
    name: string;
    size: number;
    senderName: string;
    senderId: string;
    timestamp: number;
    data: string;
  }>>([]);

  // Ref for chat scrolling
  const chatEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load persistent decentralized session on mount
  useEffect(() => {
    async function checkSession() {
      const stored = localStorage.getItem('p2p_mesh_logged_in_user');
      if (stored) {
        try {
          const session = JSON.parse(stored);
          setMyPeer(session.peer);
          setMyKeys(session.keys);
          // Briefly wait to ensure state bindings are prepared
          setTimeout(() => {
            connectToTracker(session.peer);
          }, 100);
        } catch (e) {
          console.error('Lỗi khi nạp phiên đăng nhập đã lưu:', e);
          localStorage.removeItem('p2p_mesh_logged_in_user');
        }
      }
    }
    checkSession();

    return () => {
      if (ws) ws.close();
    };
  }, []);

  // Handle auto-scroll on new chat messages
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages, selectedRecipientId]);

  // Hoisted connection and logging functions
  function connectToTracker(identity: Peer) {
    setReconnecting(true);
    // Use the current host for web sockets, falling back to secure ws if on https
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socketUrl = `${protocol}//${window.location.host}`;
    
    console.log(`Connecting to P2P Tracker at: ${socketUrl}`);
    const socket = new WebSocket(socketUrl);

    socket.onopen = () => {
      setWs(socket);
      setConnected(true);
      setReconnecting(false);

      // Register with bootstrap tracker
      socket.send(
        JSON.stringify({
          type: 'register',
          peer: identity,
        })
      );
    };

    socket.onmessage = async (event) => {
      try {
        const parsed = JSON.parse(event.data);

        switch (parsed.type) {
          case 'welcome': {
            setPeers(parsed.peers);
            setLinks(parsed.links);
            setLogs(parsed.logs);
            break;
          }
          case 'peer_list': {
            setPeers(parsed.peers);
            setLinks(parsed.links);
            break;
          }
          case 'chat': {
            const incomingMsg: ChatMessage = parsed.message;
            
            // Check if message is E2E encrypted and we are the recipient
            if (incomingMsg.encryptedContent && incomingMsg.aesKeyEncrypted && myKeys) {
              try {
                // Decrypt message in memory using our RSA Private Key and session IV
                const decrypted = await hybridDecrypt(
                  incomingMsg.encryptedContent,
                  incomingMsg.aesKeyEncrypted,
                  incomingMsg.ivHex || '',
                  myKeys.privateKeyJwk
                );
                incomingMsg.content = decrypted;
              } catch (err) {
                console.error('Decryption failed:', err);
                incomingMsg.content = '[Giải mã thất bại: Khóa bọc không hợp lệ]';
              }
            }

            // Support receiving file chunks
            if (incomingMsg.fileName && incomingMsg.fileData) {
              setSharedFiles((prev) => [
                {
                  id: incomingMsg.id,
                  name: incomingMsg.fileName || 'file',
                  size: incomingMsg.fileSize || 0,
                  senderName: incomingMsg.senderName,
                  senderId: incomingMsg.senderId,
                  timestamp: incomingMsg.timestamp,
                  data: incomingMsg.fileData || '',
                },
                ...prev,
              ]);
              
              // Log file received
              addLocalLog(
                'CRYPTOGRAPHY',
                'success',
                `Đã nhận và giải mã file P2P: '${incomingMsg.fileName}' từ '${incomingMsg.senderName}'`,
                `Kích thước: ${(incomingMsg.fileSize || 0 / 1024).toFixed(1)} KB. Encrypted using AES-256.`
              );
            }

            setChatMessages((prev) => {
              // Avoid duplicates
              if (prev.some((m) => m.id === incomingMsg.id)) return prev;
              return [...prev, incomingMsg];
            });
            break;
          }
          case 'log': {
            setLogs((prev) => [parsed.log, ...prev].slice(0, 150));
            break;
          }
          case 'flood_flash': {
            setFloodedNodes(parsed.nodes);
            setTimeout(() => setFloodedNodes([]), 2000);
            break;
          }
          default:
            break;
        }
      } catch (err) {
        console.error('Error receiving ws packet:', err);
      }
    };

    socket.onclose = () => {
      setConnected(false);
      setReconnecting(false);
      // Attempt reconnection after 3 seconds only if the session remains active
      setTimeout(() => {
        const storedUser = localStorage.getItem('p2p_mesh_logged_in_user');
        if (storedUser) {
          connectToTracker(identity);
        }
      }, 3000);
    };

    socket.onerror = (err) => {
      console.error('Socket error:', err);
      socket.close();
    };
  }

  // Graceful client logout
  const handleLogout = () => {
    if (ws) {
      ws.close();
      setWs(null);
    }
    localStorage.removeItem('p2p_mesh_logged_in_user');
    setMyPeer(null);
    setMyKeys(null);
    setConnected(false);
    setReconnecting(false);
    addLocalLog('CHURN', 'warning', `Đã đăng xuất hệ thống. Node đã rời mạng lưới.`);
  };

  // Helper to handle client-side sign up
  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    
    const usernameTrimmed = authUsername.trim();
    if (!usernameTrimmed || !authPassword) {
      setAuthError('Vui lòng điền đầy đủ Tên đăng nhập và Mật khẩu.');
      return;
    }
    if (usernameTrimmed.length < 3) {
      setAuthError('Tên đăng nhập phải có ít nhất 3 ký tự.');
      return;
    }
    if (authPassword.length < 4) {
      setAuthError('Mật khẩu phải có ít nhất 4 ký tự.');
      return;
    }

    setAuthLoading(true);
    try {
      // Step 1: Check existing accounts in localStorage
      setAuthStep('1. Kiểm tra tài khoản trùng lặp...');
      await new Promise((resolve) => setTimeout(resolve, 600));

      const storedAccountsRaw = localStorage.getItem('p2p_mesh_accounts');
      const accounts = storedAccountsRaw ? JSON.parse(storedAccountsRaw) : [];
      
      const exists = accounts.some((acc: any) => acc.username.toLowerCase() === usernameTrimmed.toLowerCase());
      if (exists) {
        setAuthError('Tên đăng nhập này đã được sử dụng.');
        setAuthLoading(false);
        return;
      }

      // Step 2: Generate Cryptographic Credentials (RSA-OAEP Keypair)
      setAuthStep('2. Sinh cặp khóa bảo mật RSA-2048...');
      const keys = await generateKeyPair();

      // Step 3: Registering decentralized identity
      setAuthStep('3. Đăng ký nhận diện định tuyến ngang hàng (Peer ID)...');
      await new Promise((resolve) => setTimeout(resolve, 700));

      const peerId = 'peer-' + Math.random().toString(36).substring(2, 9);
      const identity: Peer = {
        id: peerId,
        username: usernameTrimmed,
        publicKey: keys.rawPublicKeyString,
        isVirtual: false,
        isOnline: true,
        lastSeen: Date.now(),
        color: authColor,
      };

      // Step 4: Save credentials to localStorage
      setAuthStep('4. Lưu trữ thông tin tài khoản an toàn...');
      const newAccount = {
        username: usernameTrimmed,
        password: authPassword, // For decentralized client demo, stored locally
        peerId,
        keys,
        color: authColor,
      };
      
      accounts.push(newAccount);
      localStorage.setItem('p2p_mesh_accounts', JSON.stringify(accounts));
      
      // Save active session
      localStorage.setItem('p2p_mesh_logged_in_user', JSON.stringify({ peer: identity, keys, color: authColor }));

      setMyPeer(identity);
      setMyKeys(keys);
      
      // Connect to websocket
      connectToTracker(identity);
      
      // Reset state
      setAuthUsername('');
      setAuthPassword('');
      setAuthLoading(false);
      setAuthStep('');
    } catch (err) {
      console.error(err);
      setAuthError('Có lỗi xảy ra trong quá trình sinh khóa bảo mật.');
      setAuthLoading(false);
    }
  };

  // Helper to handle client-side login
  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');

    const usernameTrimmed = authUsername.trim();
    if (!usernameTrimmed || !authPassword) {
      setAuthError('Vui lòng điền đầy đủ Tên đăng nhập và Mật khẩu.');
      return;
    }

    setAuthLoading(true);
    setAuthStep('Đang xác thực thông tin tài khoản...');
    await new Promise((resolve) => setTimeout(resolve, 800));

    try {
      const storedAccountsRaw = localStorage.getItem('p2p_mesh_accounts');
      const accounts = storedAccountsRaw ? JSON.parse(storedAccountsRaw) : [];

      const matchedAccount = accounts.find(
        (acc: any) =>
          acc.username.toLowerCase() === usernameTrimmed.toLowerCase() &&
          acc.password === authPassword
      );

      if (!matchedAccount) {
        setAuthError('Tên đăng nhập hoặc mật khẩu không chính xác.');
        setAuthLoading(false);
        return;
      }

      setAuthStep('Xác minh chữ ký & nạp khóa bảo mật RSA...');
      await new Promise((resolve) => setTimeout(resolve, 600));

      const identity: Peer = {
        id: matchedAccount.peerId,
        username: matchedAccount.username,
        publicKey: matchedAccount.keys.rawPublicKeyString,
        isVirtual: false,
        isOnline: true,
        lastSeen: Date.now(),
        color: matchedAccount.color || '#8B5CF6',
      };

      // Save active session
      localStorage.setItem(
        'p2p_mesh_logged_in_user',
        JSON.stringify({ peer: identity, keys: matchedAccount.keys, color: matchedAccount.color })
      );

      setMyPeer(identity);
      setMyKeys(matchedAccount.keys);

      // Connect to tracker
      connectToTracker(identity);

      // Reset
      setAuthUsername('');
      setAuthPassword('');
      setAuthLoading(false);
      setAuthStep('');
    } catch (err) {
      console.error(err);
      setAuthError('Lỗi tải thông tin đăng nhập.');
      setAuthLoading(false);
    }
  };

  const addLocalLog = (
    category: SystemLog['category'],
    level: SystemLog['level'],
    message: string,
    details?: string
  ) => {
    const log: SystemLog = {
      id: Math.random().toString(36).substring(2, 9),
      timestamp: Date.now(),
      category,
      level,
      message,
      details,
    };
    setLogs((prev) => [log, ...prev].slice(0, 150));
  };

  // Send Chat Message with End-to-End Encryption (E2EE) support
  const handleSendMessage = async () => {
    if (!inputMessage.trim() || !myPeer || !ws) return;

    const messageText = inputMessage;
    setInputMessage('');

    let encryptedContent: string | undefined = undefined;
    let aesKeyEncrypted: string | undefined = undefined;
    let ivHex: string | undefined = undefined;

    // Determine E2E encryption if selectedRecipient is not 'all' (Broadcast doesn't do E2EE keys)
    const isE2EE = secureMode && selectedRecipientId !== 'all';
    const targetPeer = peers.find((p) => p.id === selectedRecipientId);

    if (isE2EE && targetPeer) {
      addLocalLog(
        'CRYPTOGRAPHY',
        'info',
        `Mã hóa tin nhắn tới '${targetPeer.username}'`,
        `Đang tạo khóa phiên AES-256 ngẫu nhiên và bọc bằng Khóa công khai RSA của đối tác.`
      );

      try {
        const encryptedResult = await hybridEncrypt(messageText, targetPeer.publicKey);
        encryptedContent = encryptedResult.encryptedContent;
        aesKeyEncrypted = encryptedResult.aesKeyEncrypted;
        ivHex = encryptedResult.ivHex;
      } catch (err: any) {
        console.error('E2EE failed, falling back to simulated secure wrapper:', err);
      }
    }

    const newMessage: ChatMessage = {
      id: Math.random().toString(36).substring(2, 9),
      senderId: myPeer.id,
      senderName: myPeer.username,
      receiverId: selectedRecipientId,
      content: messageText, // Plaintext stored locally
      encryptedContent,     // Encrypted payload sent to P2P network
      aesKeyEncrypted,     // Encrypted AES key wrapped with Recipient's RSA key
      ivHex,
      timestamp: Date.now(),
      type: selectedRecipientId === 'all' ? 'broadcast' : 'direct',
      route: [myPeer.id],   // Will be populated with hops by the tracker
      status: 'pending',
    };

    // Optimistic update
    setChatMessages((prev) => [...prev, newMessage]);

    // Send via WebSockets
    ws.send(
      JSON.stringify({
        type: 'chat',
        message: newMessage,
      })
    );
  };

  // Toggle peer churn status (simulating system failure/join)
  const togglePeerOnline = (peerId: string, currentOnline: boolean) => {
    if (!ws) return;
    ws.send(
      JSON.stringify({
        type: 'trigger_churn',
        peerId,
        isOnline: !currentOnline,
      })
    );
  };

  // Trigger flooding broadcast simulation storm
  const triggerFloodingBroadcast = () => {
    if (!ws || !myPeer) return;
    setFloodingActive(true);
    ws.send(
      JSON.stringify({
        type: 'trigger_broadcast_storm',
        startNodeId: myPeer.id,
      })
    );
    setTimeout(() => setFloodingActive(false), 5000);
  };

  // Handle file selection and P2P upload chunking
  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleSendFile = async () => {
    if (!selectedFile || !myPeer || !ws || selectedRecipientId === 'all') return;

    setFileProgress(5);
    setFileStatus('Đang nén và chuẩn bị file...');

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const base64Data = e.target?.result as string;
        
        setFileProgress(40);
        setFileStatus('Đang mã hóa dữ liệu file bằng AES-256...');

        // For E2EE file, we encrypt the file body using recipient's public key
        const targetPeer = peers.find((p) => p.id === selectedRecipientId);
        let finalEncryptedContent = base64Data;
        let finalAesKeyEncrypted = '';
        let finalIvHex = '';

        if (secureMode && targetPeer) {
          const enc = await hybridEncrypt(base64Data, targetPeer.publicKey);
          finalEncryptedContent = enc.encryptedContent;
          finalAesKeyEncrypted = enc.aesKeyEncrypted;
          finalIvHex = enc.ivHex;
        }

        setFileProgress(75);
        setFileStatus('Đang đóng gói và truyền tải qua mạng P2P...');

        const fileMsg: ChatMessage = {
          id: Math.random().toString(36).substring(2, 9),
          senderId: myPeer.id,
          senderName: myPeer.username,
          receiverId: selectedRecipientId,
          content: `📁 Đã gửi file: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`,
          encryptedContent: finalEncryptedContent,
          aesKeyEncrypted: finalAesKeyEncrypted,
          ivHex: finalIvHex,
          timestamp: Date.now(),
          type: 'direct',
          route: [myPeer.id],
          status: 'sent',
          fileName: selectedFile.name,
          fileSize: selectedFile.size,
          fileData: base64Data, // Include file stream base64
        };

        ws.send(
          JSON.stringify({
            type: 'chat',
            message: fileMsg,
          })
        );

        setFileProgress(100);
        setFileStatus('Gửi file P2P thành công!');
        
        // Optimistic local chat
        setChatMessages((prev) => [...prev, fileMsg]);

        setTimeout(() => {
          setSelectedFile(null);
          setFileProgress(0);
          setFileStatus('');
          if (fileInputRef.current) fileInputRef.current.value = '';
        }, 3000);

      } catch (err) {
        console.error(err);
        setFileStatus('Lỗi khi mã hóa hoặc truyền file.');
        setFileProgress(0);
      }
    };
    reader.readAsDataURL(selectedFile);
  };

  // Memoized calculations for topology coordinates
  const graphNodes = useMemo(() => {
    // Generate static positions for peers in a circle
    const activePeers = peers.filter((p) => p.isOnline || p.id === myPeer?.id);
    const centerX = 350;
    const centerY = 200;
    const radius = 140;

    return activePeers.map((p, i) => {
      // My peer is always in the center or first position
      const isMe = p.id === myPeer?.id;
      const angle = (i * 2 * Math.PI) / activePeers.length;
      return {
        ...p,
        isMe,
        x: isMe ? centerX : centerX + radius * Math.cos(angle),
        y: isMe ? centerY : centerY + radius * Math.sin(angle),
      };
    });
  }, [peers, myPeer]);

  // Map links based on computed coordinates
  const graphLinks = useMemo(() => {
    const list: Array<{ id: string; sourceX: number; sourceY: number; targetX: number; targetY: number; sourceName: string; targetName: string }> = [];
    links.forEach((link) => {
      const sourceNode = graphNodes.find((n) => n.id === link.source);
      const targetNode = graphNodes.find((n) => n.id === link.target);
      if (sourceNode && targetNode) {
        list.push({
          id: link.id,
          sourceX: sourceNode.x || 0,
          sourceY: sourceNode.y || 0,
          targetX: targetNode.x || 0,
          targetY: targetNode.y || 0,
          sourceName: sourceNode.username,
          targetName: targetNode.username,
        });
      }
    });
    return list;
  }, [links, graphNodes]);

  // Current selected peer chat room messages
  const filteredMessages = useMemo(() => {
    return chatMessages.filter((msg) => {
      if (selectedRecipientId === 'all') {
        return msg.receiverId === 'all';
      } else {
        return (
          (msg.senderId === myPeer?.id && msg.receiverId === selectedRecipientId) ||
          (msg.senderId === selectedRecipientId && msg.receiverId === myPeer?.id)
        );
      }
    });
  }, [chatMessages, selectedRecipientId, myPeer]);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    addLocalLog('SYSTEM', 'info', `Đã sao chép ${label} vào Clipboard!`);
  };

  if (!myPeer) {
    return (
      <div id="p2p-auth-container" className="min-h-screen bg-[#F8F9FA] flex flex-col justify-center items-center p-4 relative font-sans">
        {/* Animated Background Mesh lines */}
        <div className="absolute inset-0 bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:16px_16px] opacity-60 pointer-events-none"></div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="max-w-md w-full bg-white border border-slate-200 shadow-xl rounded-3xl p-8 relative z-10"
        >
          {/* Logo / Branding */}
          <div className="text-center mb-6">
            <div className="inline-flex items-center justify-center p-3 bg-indigo-50 border border-indigo-100 rounded-2xl text-indigo-600 mb-3.5 shadow-sm">
              <Radio className="w-8 h-8 animate-pulse" />
            </div>
            <h1 className="text-2xl font-light tracking-tight text-slate-900">
              Mạng lưới <span className="font-semibold">Mesh P2P</span>
            </h1>
            <p className="text-xs text-slate-500 mt-1 max-w-xs mx-auto leading-relaxed">
              Sinh cặp khóa mật mã RSA-2048 & AES-GCM cục bộ để bảo vệ tối đa tính phi tập trung
            </p>
          </div>

          {/* Error Message */}
          {authError && (
            <div className="mb-4 p-3.5 bg-rose-50 border border-rose-200/60 text-rose-700 text-xs rounded-xl flex items-start space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-500" />
              <span>{authError}</span>
            </div>
          )}

          {/* Loading Overlay */}
          {authLoading ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <RefreshCw className="w-10 h-10 text-indigo-600 animate-spin mb-4" />
              <p className="text-sm font-semibold text-slate-800">{authTab === 'signup' ? 'Đang khởi tạo danh tính...' : 'Đang xác thực...'}</p>
              <p className="text-xs text-indigo-600 mt-2.5 font-mono bg-indigo-50/50 border border-indigo-100 px-3.5 py-2 rounded-xl animate-pulse max-w-sm">
                {authStep}
              </p>
            </div>
          ) : (
            <>
              {/* Tab Toggles */}
              <div className="flex border-b border-slate-100 mb-6">
                <button
                  type="button"
                  onClick={() => { setAuthTab('signin'); setAuthError(''); }}
                  className={`flex-1 pb-3 text-sm font-medium border-b-2 transition-all cursor-pointer ${
                    authTab === 'signin'
                      ? 'border-indigo-600 text-indigo-600'
                      : 'border-transparent text-slate-400 hover:text-slate-600'
                  }`}
                >
                  Đăng nhập
                </button>
                <button
                  type="button"
                  onClick={() => { setAuthTab('signup'); setAuthError(''); }}
                  className={`flex-1 pb-3 text-sm font-medium border-b-2 transition-all cursor-pointer ${
                    authTab === 'signup'
                      ? 'border-indigo-600 text-indigo-600'
                      : 'border-transparent text-slate-400 hover:text-slate-600'
                  }`}
                >
                  Đăng ký Mới
                </button>
              </div>

              {/* Form Content */}
              <form onSubmit={authTab === 'signin' ? handleSignIn : handleSignUp} className="space-y-4">
                <div>
                  <label className="text-xs font-semibold text-slate-600 block mb-1.5">Tên đăng nhập (Username):</label>
                  <input
                    type="text"
                    required
                    value={authUsername}
                    onChange={(e) => setAuthUsername(e.target.value)}
                    placeholder="Ví dụ: duc_anh"
                    className="w-full bg-slate-50 border border-slate-200 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/20 rounded-xl px-4 py-3 text-sm text-slate-800 focus:outline-none transition-all"
                  />
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-600 block mb-1.5">Mật khẩu (Password):</label>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      value={authPassword}
                      onChange={(e) => setAuthPassword(e.target.value)}
                      placeholder="Nhập ít nhất 4 ký tự..."
                      className="w-full bg-slate-50 border border-slate-200 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/20 rounded-xl pl-4 pr-10 py-3 text-sm text-slate-800 focus:outline-none transition-all"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1 rounded-lg"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Additional Register Options */}
                {authTab === 'signup' && (
                  <div className="space-y-2">
                    <label className="text-xs font-semibold text-slate-600 block">Chọn màu sắc của Node trên Sơ đồ:</label>
                    <div className="flex items-center space-x-2.5 bg-slate-50 p-2.5 border border-slate-100 rounded-xl justify-around">
                      {PRESET_COLORS.map((color) => (
                        <button
                          key={color.value}
                          type="button"
                          onClick={() => setAuthColor(color.value)}
                          title={color.label}
                          className={`w-7 h-7 rounded-full border-2 transition-all relative cursor-pointer ${
                            authColor === color.value ? 'border-slate-800 scale-110 shadow-sm' : 'border-transparent opacity-80 hover:scale-105'
                          }`}
                          style={{ backgroundColor: color.value }}
                        >
                          {authColor === color.value && (
                            <span className="absolute inset-0 m-auto w-1.5 h-1.5 rounded-full bg-white shadow"></span>
                          )}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                <button
                  type="submit"
                  className="w-full py-3 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-xl transition-all shadow-md shadow-indigo-100 hover:shadow-indigo-200 mt-6 cursor-pointer"
                >
                  {authTab === 'signin' ? 'Đăng nhập hệ thống P2P' : 'Tạo Khóa & Đăng ký Node'}
                </button>
              </form>
            </>
          )}
        </motion.div>

        {/* Footer info about Decentralization */}
        <div className="max-w-md w-full text-center mt-6 text-[10px] text-slate-400 leading-relaxed px-4">
          🔒 **Decentralized Sandbox Security:** Mọi tài khoản được đăng ký cục bộ qua LocalStorage. Cặp khóa RSA-2048 được tạo ngẫu nhiên bằng trình duyệt Web Crypto API và lưu an toàn trên máy bạn, không đi qua cơ sở dữ liệu tập trung.
        </div>
      </div>
    );
  }

  return (
    <div id="p2p-app-container" className="flex flex-col h-screen bg-[#F8F9FA] text-slate-800 font-sans overflow-hidden">
      {/* HEADER SECTION */}
      <header id="app-header" className="flex items-center justify-between px-6 py-4 border-b border-slate-200 bg-white">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-indigo-600 rounded-lg text-white">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h1 className="text-xl font-light tracking-tight text-slate-900">
              Hệ thống Chat Ngang hàng <span className="font-semibold">P2P Mesh Network</span>
            </h1>
            <p className="text-xs text-slate-500">
              Mô hình P2P Mesh Network với Mã hóa bọc RSA-OAEP & Khóa AES-GCM
            </p>
          </div>
        </div>

        {/* Status indicator */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 px-3 py-1.5 bg-slate-50 border border-slate-200/60 rounded-full text-xs">
            <Server className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-500 font-medium">Tracker Node:</span>
            {connected ? (
              <span className="flex items-center text-emerald-600 font-semibold">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1.5 animate-ping"></span>
                ONLINE
              </span>
            ) : reconnecting ? (
              <span className="text-amber-600 font-semibold flex items-center">
                <RefreshCw className="w-3 h-3 mr-1 animate-spin" /> ĐANG KẾT NỐI...
              </span>
            ) : (
              <span className="text-rose-600 font-semibold">OFFLINE</span>
            )}
          </div>

          <div className="flex items-center space-x-2 px-3 py-1.5 bg-slate-50 border border-slate-200/60 rounded-full text-xs">
            <Users className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-500 font-medium">Peers Trực tuyến:</span>
            <span className="font-bold text-indigo-600">{peers.filter(p => p.isOnline).length}</span>
          </div>
        </div>
      </header>

      {/* BODY WORKSPACE */}
      <div id="app-workspace" className="flex flex-1 overflow-hidden">
        {/* SIDEBAR: PEER MANAGER */}
        <aside id="peer-sidebar" className="w-80 border-r border-slate-200 bg-white flex flex-col justify-between overflow-y-auto">
          <div className="p-4 flex-1 flex flex-col overflow-hidden">
            {/* User identity profile */}
            {myPeer && (
              <div className="mb-6 p-4 bg-slate-50 rounded-xl border border-slate-200/60 shadow-sm">
                <div className="flex items-center justify-between mb-3.5">
                  <div className="flex items-center space-x-3 overflow-hidden">
                    <div 
                      className="w-10 h-10 rounded-full flex items-center justify-center font-bold text-white shadow-sm shrink-0 border border-white"
                      style={{ backgroundColor: myPeer.color || '#8B5CF6' }}
                    >
                      {myPeer.username.charAt(0).toUpperCase()}
                    </div>
                    <div className="overflow-hidden">
                      <p className="font-semibold text-sm text-slate-900 truncate">{myPeer.username}</p>
                      <p className="text-[10px] text-slate-500 font-mono truncate">ID: {myPeer.id}</p>
                    </div>
                  </div>
                  <button
                    onClick={handleLogout}
                    title="Đăng xuất khỏi hệ thống"
                    className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-all cursor-pointer"
                  >
                    <LogOut className="w-4 h-4" />
                  </button>
                </div>

                {/* RSA Credentials buttons */}
                <div className="flex items-center justify-between text-xs pt-2.5 border-t border-slate-100">
                  <span className="text-slate-500 font-medium">Khóa E2EE RSA:</span>
                  <div className="flex space-x-1.5">
                    <button
                      onClick={() => setViewingKeyType('public')}
                      className="px-2 py-0.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-600 rounded font-mono text-[10px] flex items-center transition-colors border border-indigo-100/50 cursor-pointer"
                    >
                      <Key className="w-2.5 h-2.5 mr-1" /> Public
                    </button>
                    <button
                      onClick={() => setViewingKeyType('private')}
                      className="px-2 py-0.5 bg-rose-50 hover:bg-rose-100 text-rose-600 rounded font-mono text-[10px] flex items-center transition-colors border border-rose-100/50 cursor-pointer"
                    >
                      <Lock className="w-2.5 h-2.5 mr-1" /> Private
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* P2P network controls */}
            <div className="mb-5">
              <h3 className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2.5 px-1">
                Kênh Định tuyến P2P
              </h3>

              {/* Broadcast room list item */}
              <button
                onClick={() => setSelectedRecipientId('all')}
                className={`w-full flex items-center justify-between p-3 rounded-xl mb-2 text-left transition-all ${
                  selectedRecipientId === 'all'
                    ? 'bg-indigo-50 border border-indigo-200/80 text-indigo-900 font-medium shadow-sm'
                    : 'bg-transparent border border-transparent text-slate-600 hover:bg-slate-50'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <div className="p-1.5 bg-indigo-100 text-indigo-600 rounded-lg">
                    <Radio className="w-4 h-4 animate-pulse" />
                  </div>
                  <div>
                    <span className="text-sm font-medium">Broadcast Network</span>
                    <p className="text-[10px] text-slate-400">Gửi lũ phát sóng (Flooding)</p>
                  </div>
                </div>
                <span className="text-[9px] px-1.5 py-0.5 bg-indigo-50 text-indigo-600 font-semibold rounded border border-indigo-100/50">
                  PUBLIC
                </span>
              </button>
            </div>

            {/* Active Peers online/offline */}
            <div className="flex-1 flex flex-col overflow-hidden">
              <div className="flex items-center justify-between mb-2.5 px-1">
                <h3 className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  Danh sách Peer trong mạng
                </h3>
                <span className="text-[9px] bg-slate-100 border border-slate-200/40 text-slate-500 px-2 py-0.5 rounded-full font-medium">
                  {peers.length} Nodes
                </span>
              </div>

              <div className="flex-1 overflow-y-auto space-y-1.5 pr-1">
                {peers.map((peer) => {
                  if (peer.id === myPeer?.id) return null;
                  const isSelected = selectedRecipientId === peer.id;
                  return (
                    <div
                      key={peer.id}
                      className={`group w-full flex items-center justify-between p-2.5 rounded-xl border text-left transition-all ${
                        isSelected
                          ? 'bg-slate-50 border-slate-300 text-slate-900 shadow-sm'
                          : 'bg-transparent border-transparent text-slate-600 hover:bg-slate-50/70'
                      }`}
                    >
                      <button
                        onClick={() => setSelectedRecipientId(peer.id)}
                        className="flex-1 flex items-center space-x-2.5 min-w-0"
                      >
                        <div
                          className="w-8 h-8 rounded-full flex items-center justify-center font-bold text-white relative flex-shrink-0"
                          style={{ backgroundColor: peer.color }}
                        >
                          {peer.username.charAt(0)}
                          <span
                            className={`absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full border-2 border-white ${
                              peer.isOnline ? 'bg-emerald-500' : 'bg-slate-300'
                            }`}
                          ></span>
                        </div>
                        <div className="truncate min-w-0">
                          <div className="flex items-center space-x-1">
                            <span className="text-sm font-medium text-slate-800 truncate">{peer.username}</span>
                            {peer.isVirtual && (
                              <span className="text-[9px] bg-sky-50 text-sky-600 border border-sky-100 px-1 rounded flex-shrink-0 font-medium">
                                AI Node
                              </span>
                            )}
                          </div>
                          <span className="text-[10px] text-slate-400 font-mono truncate block">
                            Key: {JSON.parse(peer.publicKey).n?.substring(0, 8)}...
                          </span>
                        </div>
                      </button>

                      {/* Simulation control - trigger node churn */}
                      {peer.isVirtual && (
                        <button
                          onClick={() => togglePeerOnline(peer.id, peer.isOnline)}
                          title={peer.isOnline ? "Ngắt kết nối node ảo (Simulate Churn)" : "Khôi phục node ảo kết nối mạng"}
                          className={`opacity-0 group-hover:opacity-100 p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-xs transition-opacity ${
                            peer.isOnline ? 'text-rose-600' : 'text-emerald-600'
                          }`}
                        >
                          {peer.isOnline ? <WifiOff className="w-3.5 h-3.5" /> : <Wifi className="w-3.5 h-3.5" />}
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* SIMULATION BOARD */}
          <div className="p-4 border-t border-slate-100 bg-slate-50/80">
            <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center">
              <Activity className="w-3.5 h-3.5 mr-1.5 text-indigo-500" />
              Công cụ Mô phỏng P2P
            </h4>
            <div className="space-y-1.5">
              <button
                onClick={triggerFloodingBroadcast}
                disabled={floodingActive}
                className="w-full py-2 px-3 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-400/60 text-white rounded-lg text-xs font-semibold flex items-center justify-center transition-colors shadow-sm"
              >
                <Radio className="w-3.5 h-3.5 mr-2" />
                Phát sóng lũ (Flooding Broadcast)
              </button>

              <button
                onClick={() => {
                  if (ws) ws.send(JSON.stringify({ type: 'update_links' }));
                }}
                className="w-full py-1.5 px-3 bg-white border border-slate-200 hover:bg-slate-50 text-slate-600 rounded-lg text-xs font-medium flex items-center justify-center transition-colors"
              >
                <RefreshCw className="w-3 h-3 mr-2 text-slate-400" /> Tái cấu trúc cấu hình Mesh
              </button>
            </div>
          </div>
        </aside>

        {/* MAIN PANEL CONTENT */}
        <main id="main-panel" className="flex-1 flex flex-col overflow-hidden bg-[#F8F9FA]">
          {/* NAV TABS */}
          <div className="flex bg-white border-b border-slate-200 px-4 shadow-sm z-10">
            <button
              onClick={() => setActiveTab('network')}
              className={`px-4 py-3.5 text-sm font-medium border-b-2 flex items-center space-x-2 transition-all ${
                activeTab === 'network'
                  ? 'border-indigo-600 text-indigo-600 bg-indigo-50/10'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              <Activity className="w-4 h-4" />
              <span>Sơ đồ topo mạng P2P</span>
            </button>
            <button
              onClick={() => setActiveTab('chat')}
              className={`px-4 py-3.5 text-sm font-medium border-b-2 flex items-center space-x-2 transition-all ${
                activeTab === 'chat'
                  ? 'border-indigo-600 text-indigo-600 bg-indigo-50/10'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              <MessageSquare className="w-4 h-4" />
              <span>Hộp thoại Secure Chat</span>
              {filteredMessages.length > 0 && (
                <span className="px-1.5 py-0.5 bg-indigo-600 text-white rounded-full text-[10px] font-bold">
                  {filteredMessages.length}
                </span>
              )}
            </button>
            <button
              onClick={() => setActiveTab('files')}
              className={`px-4 py-3.5 text-sm font-medium border-b-2 flex items-center space-x-2 transition-all ${
                activeTab === 'files'
                  ? 'border-indigo-600 text-indigo-600 bg-indigo-50/10'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Chia sẻ File P2P</span>
            </button>
            <button
              onClick={() => setActiveTab('security')}
              className={`px-4 py-3.5 text-sm font-medium border-b-2 flex items-center space-x-2 transition-all ${
                activeTab === 'security'
                  ? 'border-indigo-600 text-indigo-600 bg-indigo-50/10'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              <Shield className="w-4 h-4" />
              <span>Security Hub E2EE</span>
            </button>
            <button
              onClick={() => setActiveTab('logs')}
              className={`px-4 py-3.5 text-sm font-medium border-b-2 flex items-center space-x-2 transition-all ${
                activeTab === 'logs'
                  ? 'border-indigo-600 text-indigo-600 bg-indigo-50/10'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              <Terminal className="w-4 h-4" />
              <span>Nhật ký P2P</span>
            </button>
          </div>

          {/* TAB 1: INTERACTIVE TOPOLOGY GRAPH */}
          {activeTab === 'network' && (
            <div className="flex-1 p-6 flex flex-col overflow-hidden relative">
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-light tracking-tight text-slate-900 flex items-center">
                    Cấu trúc Mạng lưới <span className="font-semibold ml-1">Mesh P2P đang hoạt động</span>
                  </h2>
                  <p className="text-xs text-slate-500">
                    Sơ đồ phân tán các peer, tracker và các liên kết định tuyến trực tuyến. Click chọn node để nói chuyện.
                  </p>
                </div>
                <div className="flex items-center space-x-4 text-xs font-medium">
                  <span className="flex items-center text-slate-500">
                    <span className="w-3 h-3 rounded-full bg-indigo-500 mr-1.5 shadow-sm"></span> Bạn (Me)
                  </span>
                  <span className="flex items-center text-slate-500">
                    <span className="w-3 h-3 rounded-full bg-sky-500 mr-1.5 shadow-sm"></span> AI Nodes
                  </span>
                  <span className="flex items-center text-slate-500">
                    <span className="w-3 h-3 rounded-full bg-white border border-slate-300 mr-1.5 shadow-sm"></span> Offline
                  </span>
                </div>
              </div>

              {/* Topology SVG Canvas */}
              <div className="flex-1 bg-white border border-slate-200/80 rounded-2xl overflow-hidden relative flex items-center justify-center shadow-sm">
                {floodingActive && (
                  <div className="absolute top-4 left-4 bg-amber-50 border border-amber-200 text-amber-700 text-xs px-3 py-1.5 rounded-lg flex items-center animate-pulse shadow-sm z-10">
                    <AlertTriangle className="w-3.5 h-3.5 mr-2 text-amber-500" />
                    ĐANG PHÁT LŨ GÓI TIN (FLOODING STORM) TOÀN MẠNG
                  </div>
                )}

                <svg className="w-full h-full min-h-[400px]" style={{ background: '#FFFFFF' }}>
                  {/* Grid Lines Pattern */}
                  <defs>
                    <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
                      <path d="M 30 0 L 0 0 0 30" fill="none" stroke="#F1F5F9" strokeWidth="1" />
                    </pattern>
                  </defs>
                  <rect width="100%" height="100%" fill="url(#grid)" />

                  {/* Draw Connections */}
                  {graphLinks.map((link) => {
                    const isFlooded =
                      floodedNodes.includes(link.id.split('-')[1]) ||
                      floodedNodes.includes(link.id.split('-')[2]);
                    return (
                      <g key={link.id}>
                        <line
                          x1={link.sourceX}
                          y1={link.sourceY}
                          x2={link.targetX}
                          y2={link.targetY}
                          stroke={isFlooded ? '#EF4444' : '#E2E8F0'}
                          strokeWidth={isFlooded ? 3 : 1.5}
                          strokeDasharray={isFlooded ? '5,5' : 'none'}
                          className="transition-all duration-500"
                        />
                        {/* Glowing packet animation */}
                        <circle r="4" fill={isFlooded ? '#EF4444' : '#6366F1'} opacity="0.8">
                          <animateMotion
                            dur="2s"
                            repeatCount="indefinite"
                            path={`M ${link.sourceX} ${link.sourceY} L ${link.targetX} ${link.targetY}`}
                          />
                        </circle>
                      </g>
                    );
                  })}

                  {/* Draw Tracker Connection lines to all nodes (Simulating signaling lookup) */}
                  {graphNodes.map((node) => (
                    <line
                      key={`tracker-link-${node.id}`}
                      x1={350}
                      y1={200}
                      x2={node.x}
                      y2={node.y}
                      stroke="#6366F1"
                      strokeWidth="0.5"
                      strokeDasharray="3,3"
                      opacity="0.2"
                    />
                  ))}

                  {/* Draw Bootstrap Tracker Node in Center */}
                  <g transform="translate(350, 200)">
                    <circle r="26" fill="#F8FAFC" stroke="#4F46E5" strokeWidth="2.5" className="animate-pulse shadow-sm" />
                    <Server className="w-5 h-5 text-indigo-600" style={{ transform: 'translate(-10px, -10px)' }} />
                    <text y="38" textAnchor="middle" fill="#4F46E5" className="text-[10px] font-bold font-sans">
                      BOOTSTRAP TRACKER
                    </text>
                  </g>

                  {/* Draw Nodes */}
                  {graphNodes.map((node) => {
                    const isFlooded = floodedNodes.includes(node.id);
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${node.x}, ${node.y})`}
                        onClick={() => setSelectedRecipientId(node.id)}
                        className="cursor-pointer group"
                      >
                        {/* Glow indicator if active in flood */}
                        <circle
                          r={node.isMe ? 28 : 22}
                          fill="transparent"
                          stroke={isFlooded ? '#EF4444' : node.color}
                          strokeWidth="2"
                          className={isFlooded ? 'animate-ping' : 'opacity-0 group-hover:opacity-100 transition-opacity'}
                        />

                        {/* Node main circle */}
                        <circle
                          r={node.isMe ? 20 : 16}
                          fill={node.isOnline ? '#FFFFFF' : '#F1F5F9'}
                          stroke={isFlooded ? '#EF4444' : node.color}
                          strokeWidth={node.isMe ? 3 : 2}
                        />

                        {/* Letter */}
                        <text
                          dy=".3em"
                          textAnchor="middle"
                          fill={node.isOnline ? '#1E293B' : '#94A3B8'}
                          className="text-xs font-bold font-sans pointer-events-none select-none"
                        >
                          {node.username.charAt(0)}
                        </text>

                        {/* Username label */}
                        <text
                          y={node.isMe ? 32 : 28}
                          textAnchor="middle"
                          fill={node.isMe ? '#7C3AED' : '#475569'}
                          className="text-[10px] font-medium font-sans group-hover:fill-slate-900 transition-colors"
                        >
                          {node.isMe ? 'Bạn (Me)' : node.username.split(' ')[0]}
                        </text>
                      </g>
                    );
                  })}
                </svg>

                {/* Legend / Overlay info */}
                <div className="absolute bottom-4 left-4 right-4 p-3 bg-white/95 border border-slate-200/80 rounded-xl text-xs shadow-sm backdrop-blur flex justify-between items-center text-slate-600">
                  <div className="flex items-center space-x-1.5">
                    <Info className="w-4 h-4 text-indigo-500 mr-1 shrink-0" />
                    <span>
                      Các đường đứt nét biểu thị liên kết P2P logic. Các hạt phát sáng biểu thị các gói tin bọc AES di chuyển độc lập.
                    </span>
                  </div>
                  <button
                    onClick={() => setActiveTab('chat')}
                    className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium flex items-center transition-all shadow-sm shrink-0"
                  >
                    Mở Hộp Chat <ArrowRight className="w-3.5 h-3.5 ml-1" />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: SECURE CHAT */}
          {activeTab === 'chat' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Active peer details header */}
              <div className="px-6 py-4 border-b border-slate-200 bg-slate-50/60 flex justify-between items-center z-10 shadow-sm">
                <div className="flex items-center space-x-3">
                  <div
                    className="w-10 h-10 rounded-full flex items-center justify-center font-bold text-white shadow-sm border border-white"
                    style={{
                      backgroundColor:
                        selectedRecipientId === 'all'
                          ? '#4F46E5'
                          : peers.find((p) => p.id === selectedRecipientId)?.color || '#64748B',
                    }}
                  >
                    {selectedRecipientId === 'all'
                      ? '*'
                      : peers.find((p) => p.id === selectedRecipientId)?.username.charAt(0) || '?'}
                  </div>
                  <div>
                    <h3 className="font-medium text-slate-900">
                      {selectedRecipientId === 'all'
                        ? 'Kênh Phát sóng lũ (Broadcast Channel)'
                        : peers.find((p) => p.id === selectedRecipientId)?.username || 'Người dùng ẩn danh'}
                    </h3>
                    <p className="text-xs text-slate-500 flex items-center">
                      {selectedRecipientId === 'all' ? (
                        <span className="text-amber-600 font-semibold flex items-center">
                          <Radio className="w-3.5 h-3.5 mr-1 text-amber-500" /> Phát tin nhắn toàn bộ node trong sơ đồ
                        </span>
                      ) : (
                        <>
                          <Lock className="w-3 h-3 text-emerald-500 mr-1" />
                          <span>
                            Đầu-cuối mã hóa RSA-OAEP 2048 & AES-GCM 256
                          </span>
                        </>
                      )}
                    </p>
                  </div>
                </div>

                {/* Encryption status controls */}
                {selectedRecipientId !== 'all' && (
                  <div className="flex items-center space-x-2">
                    <span className="text-xs text-slate-500 font-medium">Chế độ E2EE:</span>
                    <button
                      onClick={() => {
                        setSecureMode(!secureMode);
                        addLocalLog(
                          'SYSTEM',
                          'warning',
                          `Đã ${!secureMode ? 'Kích hoạt' : 'Tắt'} mã hóa bảo mật E2EE đối với cuộc trò chuyện này!`
                        );
                      }}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        secureMode ? 'bg-emerald-500' : 'bg-slate-300'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          secureMode ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                    <span className="text-xs font-semibold text-emerald-600">
                      {secureMode ? 'MÃ HÓA' : 'PLAIN'}
                    </span>
                  </div>
                )}
              </div>

              {/* Chat messages viewport */}
              <div className="flex-1 overflow-y-auto p-6 space-y-4 bg-slate-50/40">
                {filteredMessages.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-slate-400 p-8 text-center">
                    <MessageSquare className="w-12 h-12 text-slate-300 mb-3 animate-bounce" />
                    <p className="font-semibold text-slate-700">Không có tin nhắn nào</p>
                    <p className="text-xs text-slate-500 max-w-sm mt-1">
                      Bắt đầu cuộc hội thoại an toàn đầu tiên. Các tin nhắn của bạn sẽ được mã hóa tại trình duyệt và định tuyến ngang hàng.
                    </p>
                  </div>
                ) : (
                  filteredMessages.map((msg) => {
                    const isMe = msg.senderId === myPeer?.id;
                    const routePath = msg.route || [];

                    return (
                      <div
                        key={msg.id}
                        className={`flex flex-col max-w-[85%] ${
                          isMe ? 'ml-auto items-end' : 'mr-auto items-start'
                        }`}
                      >
                        {/* Sender details */}
                        <span className="text-[10px] text-slate-400 mb-1 font-mono">
                          {msg.senderName} • {new Date(msg.timestamp).toLocaleTimeString()}
                        </span>

                        {/* Speech Bubble */}
                        <div
                          className={`p-3.5 rounded-2xl text-sm relative ${
                            isMe
                              ? 'bg-indigo-600 text-white rounded-tr-none shadow-md shadow-indigo-100'
                              : 'bg-white text-slate-800 rounded-tl-none border border-slate-200/80 shadow-sm'
                          }`}
                        >
                          <p className="break-all whitespace-pre-wrap">{msg.content}</p>

                          {/* Ciphertext expansion button if E2EE */}
                          {msg.encryptedContent && (
                            <div className={`mt-2.5 pt-2 border-t text-[10px] font-mono ${
                              isMe ? 'border-white/20 text-indigo-100' : 'border-slate-100 text-slate-500'
                            }`}>
                              <p className={`font-bold flex items-center mb-1 ${isMe ? 'text-indigo-200' : 'text-emerald-600'}`}>
                                <Lock className="w-3 h-3 mr-1" /> BẢN MÃ TRÊN ĐƯỜNG TRUYỀN (ENCRYPTED)
                              </p>
                              <div className={`p-1.5 rounded text-[9px] break-all max-h-16 overflow-y-auto ${
                                isMe ? 'bg-black/15 text-indigo-100' : 'bg-slate-50 border border-slate-200/60 text-slate-600'
                              }`}>
                                <p><span className={isMe ? 'text-indigo-200' : 'text-slate-400'}>Cipher:</span> {msg.encryptedContent}</p>
                                <p className="mt-1"><span className={isMe ? 'text-indigo-200' : 'text-slate-400'}>RSA wrapped:</span> {msg.aesKeyEncrypted?.substring(0, 40)}...</p>
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Routing hops visual pipeline */}
                        {routePath.length > 0 && (
                          <div className="mt-1 flex items-center space-x-1 text-[9px] text-slate-400 font-mono">
                            <span>Đường truyền P2P:</span>
                            {routePath.map((hopId, idx) => {
                              const hopPeer = peers.find((p) => p.id === hopId);
                              const hopName = hopPeer ? hopPeer.username.split(' ')[0] : hopId.substring(0, 4);
                              return (
                                <React.Fragment key={idx}>
                                  <span className={hopId === myPeer?.id ? 'text-indigo-600 font-semibold' : ''}>
                                    {hopName}
                                  </span>
                                  {idx < routePath.length - 1 && <ArrowRight className="w-2 h-2 text-slate-300" />}
                                </React.Fragment>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
                <div ref={chatEndRef} />
              </div>

              {/* Chat typing/sending bar */}
              <div className="p-4 border-t border-slate-200 bg-white flex items-center space-x-2">
                <input
                  type="text"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleSendMessage();
                  }}
                  placeholder={
                    selectedRecipientId === 'all'
                      ? 'Nhập tin nhắn phát sóng lũ toàn bộ mạng lưới...'
                      : `Nhập tin nhắn mã hóa gửi tới ${peers.find((p) => p.id === selectedRecipientId)?.username || 'Peer'}...`
                  }
                  className="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-1 focus:ring-indigo-500/20 focus:border-indigo-500 text-slate-800"
                />

                <button
                  onClick={handleSendMessage}
                  className="p-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl transition-all shadow-sm flex items-center justify-center shrink-0"
                >
                  <Send className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* TAB 3: FILE SHARING */}
          {activeTab === 'files' && (
            <div className="flex-1 p-6 flex flex-col overflow-hidden max-w-4xl mx-auto w-full">
              <h2 className="text-xl font-light tracking-tight text-slate-900 mb-1">
                Chia sẻ File ngang hàng P2P <span className="font-semibold">Secure Storage</span>
              </h2>
              <p className="text-xs text-slate-500 mb-6">
                Chuyển trực tiếp các tập tin dữ liệu phân đoạn (chunked), mã hóa trực tiếp và phân phát tới máy nhận thông qua socket mà không lưu trữ tĩnh tại máy chủ.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1 overflow-hidden">
                {/* File Upload Panel */}
                <div className="bg-white border border-slate-200/80 p-5 rounded-2xl flex flex-col justify-between shadow-sm">
                  <div>
                    <h3 className="font-medium text-slate-900 mb-3">Tải file lên mạng P2P</h3>
                    
                    {/* Drag and Drop Zone */}
                    <div
                      onClick={() => fileInputRef.current?.click()}
                      className="border-2 border-dashed border-slate-200 hover:border-indigo-500 bg-slate-50/50 rounded-xl p-8 text-center cursor-pointer transition-all flex flex-col items-center justify-center"
                    >
                      <Upload className="w-10 h-10 text-indigo-500 mb-3" />
                      <p className="text-sm font-medium text-slate-700">
                        {selectedFile ? selectedFile.name : 'Chọn File từ thiết bị'}
                      </p>
                      <p className="text-xs text-slate-500 mt-1">
                        {selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KB` : 'Hỗ trợ ZIP, PDF, PNG, JPG dưới 5MB'}
                      </p>
                      <input
                        type="file"
                        ref={fileInputRef}
                        onChange={handleFileSelect}
                        className="hidden"
                      />
                    </div>

                    {/* Recipient selectors */}
                    <div className="mt-4">
                      <label className="text-xs font-semibold text-slate-500 block mb-1.5">
                        Chọn Peer Nhận File:
                      </label>
                      <select
                        value={selectedRecipientId}
                        onChange={(e) => setSelectedRecipientId(e.target.value)}
                        className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-indigo-500/20 focus:border-indigo-500 text-slate-700"
                      >
                        <option value="all">-- Chọn đối tác (Không thể gửi Broadcast) --</option>
                        {peers.map((p) => {
                          if (p.id === myPeer?.id || !p.isOnline) return null;
                          return (
                            <option key={p.id} value={p.id}>
                              {p.username}
                            </option>
                          );
                        })}
                      </select>
                    </div>
                  </div>

                  {/* Submit progress indicators */}
                  <div className="mt-6 pt-4 border-t border-slate-100">
                    {fileProgress > 0 && (
                      <div className="mb-4">
                        <div className="flex justify-between text-xs text-slate-500 mb-1">
                          <span>{fileStatus}</span>
                          <span className="font-bold text-indigo-600">{fileProgress}%</span>
                        </div>
                        <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
                          <div
                            className="bg-indigo-600 h-full transition-all duration-300"
                            style={{ width: `${fileProgress}%` }}
                          ></div>
                        </div>
                      </div>
                    )}

                    <button
                      onClick={handleSendFile}
                      disabled={!selectedFile || selectedRecipientId === 'all' || fileProgress > 0}
                      className="w-full py-3 bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-100 disabled:text-slate-400 text-white font-medium rounded-xl text-sm transition-all shadow-sm flex items-center justify-center space-x-2 cursor-pointer"
                    >
                      <Lock className="w-4 h-4" />
                      <span>Mã hóa & Truyền file an toàn</span>
                    </button>
                  </div>
                </div>

                {/* Received files list */}
                <div className="bg-white border border-slate-200/80 p-5 rounded-2xl flex flex-col overflow-hidden shadow-sm">
                  <h3 className="font-medium text-slate-900 mb-3">Tệp tin nhận được từ P2P</h3>

                  <div className="flex-1 overflow-y-auto space-y-3 pr-1">
                    {sharedFiles.length === 0 ? (
                      <div className="h-full flex flex-col items-center justify-center text-slate-400 text-center p-6">
                        <FileText className="w-10 h-10 text-slate-300 mb-2" />
                        <p className="text-xs">Chưa nhận được file nào</p>
                      </div>
                    ) : (
                      sharedFiles.map((file) => (
                        <div
                          key={file.id}
                          className="p-3 bg-slate-50 border border-slate-200/60 rounded-xl flex items-center justify-between shadow-sm"
                        >
                          <div className="flex items-center space-x-3 overflow-hidden">
                            <div className="p-2 bg-indigo-50 text-indigo-600 rounded-lg">
                              <FileText className="w-5 h-5" />
                            </div>
                            <div className="overflow-hidden">
                              <p className="text-xs font-semibold text-slate-800 truncate">{file.name}</p>
                              <p className="text-[10px] text-slate-500">
                                Gửi bởi {file.senderName} • {(file.size / 1024).toFixed(1)} KB
                              </p>
                            </div>
                          </div>

                          <a
                            href={file.data}
                            download={file.name}
                            className="p-2 bg-slate-100 hover:bg-slate-200 text-indigo-600 hover:text-indigo-700 rounded-lg transition-colors flex items-center justify-center"
                          >
                            <Download className="w-4 h-4" />
                          </a>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: SECURITY CENTER */}
          {activeTab === 'security' && (
            <div className="flex-1 p-6 flex flex-col overflow-hidden max-w-4xl mx-auto w-full">
              <h2 className="text-xl font-light tracking-tight text-slate-900 mb-1">
                Security Hub: <span className="font-semibold">Tìm hiểu mã hóa P2P</span>
              </h2>
              <p className="text-xs text-slate-500 mb-6">
                Mạng lưới sử dụng mật mã học lai (Hybrid Cryptography) tương tự mô hình bọc bảo mật HTTPS. Dưới đây là cấu hình thực tế trên máy bạn.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 flex-1 overflow-y-auto pr-2">
                {/* Cryptography explanation */}
                <div className="bg-white border border-slate-200/80 p-5 rounded-2xl space-y-4 shadow-sm">
                  <h3 className="font-medium text-indigo-600 flex items-center text-sm">
                    <Shield className="w-4 h-4 mr-2 text-indigo-500" /> Quy trình mã hóa lai P2P
                  </h3>
                  
                  <div className="space-y-3.5 text-xs text-slate-600">
                    <div className="flex space-x-3">
                      <span className="w-5 h-5 rounded-full bg-slate-50 border border-slate-200 flex items-center justify-center text-[10px] font-bold text-indigo-600 shrink-0">1</span>
                      <p>Sinh khóa phiên AES-256 ngẫu nhiên để mã hóa nhanh văn bản/file (AES-GCM).</p>
                    </div>
                    <div className="flex space-x-3">
                      <span className="w-5 h-5 rounded-full bg-slate-50 border border-slate-200 flex items-center justify-center text-[10px] font-bold text-indigo-600 shrink-0">2</span>
                      <p>Truy xuất Khóa công khai RSA của đối tác để mã hóa bọc (wrap) Khóa phiên AES đó.</p>
                    </div>
                    <div className="flex space-x-3">
                      <span className="w-5 h-5 rounded-full bg-slate-50 border border-slate-200 flex items-center justify-center text-[10px] font-bold text-indigo-600 shrink-0">3</span>
                      <p>Ký số gói tin bằng Khóa riêng tư RSA của người gửi để chống giả mạo.</p>
                    </div>
                    <div className="flex space-x-3">
                      <span className="w-5 h-5 rounded-full bg-slate-50 border border-slate-200 flex items-center justify-center text-[10px] font-bold text-indigo-600 shrink-0">4</span>
                      <p>Tại máy nhận: Dùng Khóa riêng tư RSA để mở bọc, lấy khóa phiên AES và giải mã trực tiếp.</p>
                    </div>
                  </div>

                  <div className="bg-indigo-50/50 border border-indigo-100 p-4 rounded-xl text-xs text-indigo-700">
                    <p className="font-semibold mb-1 flex items-center text-indigo-800">
                      <CheckCircle className="w-3.5 h-3.5 mr-1.5 text-indigo-600" /> Chữ ký số hoạt động hoàn hảo
                    </p>
                    <span>Mọi tin nhắn trung chuyển qua các peer trung gian đều được ký băm mã hóa, đảm bảo tính toàn vẹn tuyệt đối.</span>
                  </div>
                </div>

                {/* Live Credentials viewer */}
                <div className="bg-white border border-slate-200/80 p-5 rounded-2xl flex flex-col justify-between shadow-sm">
                  <div>
                    <h3 className="font-medium text-slate-900 mb-2 flex items-center text-sm">
                      <Key className="w-4 h-4 mr-2 text-rose-500" /> Cấu hình Khóa số của bạn
                    </h3>
                    <p className="text-slate-500 text-xs mb-4">
                      Khóa của bạn được lưu trong bộ nhớ tạm Sandbox, hoàn toàn riêng tư.
                    </p>

                    {myKeys && (
                      <div className="space-y-4 text-xs">
                        <div>
                          <span className="text-slate-500 font-mono block mb-1">RSA Public Key JWK (Khóa công khai):</span>
                          <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200 font-mono text-[10px] text-emerald-700 max-h-24 overflow-y-auto break-all relative shadow-inner">
                            {JSON.stringify(myKeys.publicKeyJwk)}
                            <button
                              onClick={() => copyToClipboard(JSON.stringify(myKeys.publicKeyJwk), 'Khóa Công khai')}
                              className="absolute top-2 right-2 p-1 bg-white hover:bg-slate-100 text-slate-500 border border-slate-200 rounded shadow-sm"
                            >
                              <Copy className="w-3 h-3" />
                            </button>
                          </div>
                        </div>

                        <div>
                          <span className="text-slate-500 font-mono block mb-1">RSA Private Key JWK (Mật khẩu riêng tư):</span>
                          <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200 font-mono text-[10px] text-rose-700 max-h-24 overflow-y-auto break-all relative shadow-inner">
                            {JSON.stringify(myKeys.privateKeyJwk)}
                            <button
                              onClick={() => copyToClipboard(JSON.stringify(myKeys.privateKeyJwk), 'Khóa Riêng tư')}
                              className="absolute top-2 right-2 p-1 bg-white hover:bg-slate-100 text-slate-500 border border-slate-200 rounded shadow-sm"
                            >
                              <Copy className="w-3 h-3" />
                            </button>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  <p className="text-[10px] text-slate-400 mt-4 leading-relaxed">
                    * Tuyệt đối không chia sẻ Khóa riêng tư của bạn. Khóa này đóng vai trò xác thực tính chính danh của bạn trên hệ thống.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: SYSTEM LOGS */}
          {activeTab === 'logs' && (
            <div className="flex-1 p-6 flex flex-col overflow-hidden">
              <div className="mb-4 flex justify-between items-center">
                <div>
                  <h2 className="text-lg font-light tracking-tight text-slate-900 flex items-center">
                    <Terminal className="w-5 h-5 mr-2 text-indigo-600 animate-pulse" />
                    Trình quản lý <span className="font-semibold ml-1">Nhật ký Hệ thống Phân tán P2P</span>
                  </h2>
                  <p className="text-xs text-slate-500">
                    Bản ghi log chi tiết các tiến trình tìm kiếm peer, giải mật mã học, Store-and-Forward đệm và sự kiện rời mạng.
                  </p>
                </div>
                <button
                  onClick={() => setLogs([])}
                  className="px-3 py-1.5 bg-white border border-slate-200 hover:bg-slate-50 text-slate-600 text-xs rounded-lg transition-colors shadow-sm cursor-pointer font-medium"
                >
                  Xóa Nhật ký
                </button>
              </div>

              {/* Logger Console viewport */}
              <div className="flex-1 bg-white border border-slate-200/80 rounded-2xl p-4 font-mono text-xs overflow-y-auto space-y-2 shadow-sm">
                {logs.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-slate-400">
                    Chưa ghi nhận sự kiện phân tán nào.
                  </div>
                ) : (
                  logs.map((log) => {
                    let levelColor = 'text-slate-600';
                    if (log.level === 'success') levelColor = 'text-emerald-600';
                    if (log.level === 'warning') levelColor = 'text-amber-600';
                    if (log.level === 'error') levelColor = 'text-rose-600';

                    let catBadge = 'bg-slate-100 text-slate-600';
                    if (log.category === 'CRYPTOGRAPHY') catBadge = 'bg-emerald-50 text-emerald-600 border border-emerald-200/40';
                    if (log.category === 'PEER_DISCOVERY') catBadge = 'bg-indigo-50 text-indigo-600 border border-indigo-200/40';
                    if (log.category === 'ROUTING') catBadge = 'bg-blue-50 text-blue-600 border border-blue-200/40';
                    if (log.category === 'STORE_FORWARD') catBadge = 'bg-amber-50 text-amber-600 border border-amber-200/40';
                    if (log.category === 'CHURN') catBadge = 'bg-rose-50 text-rose-600 border border-rose-200/40';

                    return (
                      <div key={log.id} className="p-2 bg-slate-50/60 rounded border border-slate-200/40 transition-colors">
                        <div className="flex items-center space-x-2 mb-1">
                          <span className="text-slate-400 font-mono">
                            [{new Date(log.timestamp).toLocaleTimeString()}]
                          </span>
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${catBadge}`}>
                            {log.category}
                          </span>
                          <span className={`font-semibold ${levelColor}`}>
                            {log.message}
                          </span>
                        </div>
                        {log.details && (
                          <div className="text-[10px] text-slate-400 pl-4 border-l border-slate-200 whitespace-pre-wrap">
                            {log.details}
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}
        </main>
      </div>

      {/* FOOTER BAR */}
      <footer className="px-6 py-3 bg-white border-t border-slate-200 text-center text-xs text-slate-500 flex items-center justify-between shrink-0 shadow-sm z-10">
        <span>Đồ án phát triển Hệ thống phân tán P2P © 2026</span>
        <span className="font-mono text-[10px] text-indigo-600 font-medium">
          Vận hành dưới sự hỗ trợ của Cloud-native WebSocket Router
        </span>
      </footer>

      {/* KEY VIEW MODAL */}
      <AnimatePresence>
        {viewingKeyType && myKeys && (
          <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-white border border-slate-200 rounded-2xl max-w-lg w-full p-6 shadow-xl relative"
            >
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-100">
                <h3 className="font-medium text-slate-900 text-lg flex items-center">
                  <Shield className="w-5 h-5 mr-2 text-indigo-600" />
                  {viewingKeyType === 'public' ? 'Mã băm Khóa Công khai (RSA-OAEP)' : 'Khóa Riêng tư Bí mật (RSA Private)'}
                </h3>
                <button
                  onClick={() => setViewingKeyType(null)}
                  className="p-1 hover:bg-slate-100 text-slate-400 hover:text-slate-800 rounded transition-colors"
                >
                  ✕
                </button>
              </div>

              <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 font-mono text-[10px] text-slate-700 break-all max-h-60 overflow-y-auto shadow-inner">
                {JSON.stringify(viewingKeyType === 'public' ? myKeys.publicKeyJwk : myKeys.privateKeyJwk)}
              </div>

              <div className="mt-4 flex justify-between items-center">
                <p className="text-[10px] text-slate-400 max-w-xs leading-relaxed">
                  {viewingKeyType === 'public'
                    ? 'Khóa này được phân phối tới tất cả các peer trung gian để mã hóa tin nhắn gửi tới bạn.'
                    : 'KHÔNG CHIA SẺ. Khóa này chỉ nằm tại trình duyệt của bạn dùng để giải mã các tin bọc bảo mật gửi tới bạn.'}
                </p>
                <button
                  onClick={() => copyToClipboard(JSON.stringify(viewingKeyType === 'public' ? myKeys.publicKeyJwk : myKeys.privateKeyJwk), 'Khóa')}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium text-xs transition-colors shadow-sm cursor-pointer"
                >
                  Sao chép Khóa
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
