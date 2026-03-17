import { useEffect, useRef, useState, useCallback } from 'react';
import { api, type Message, type User } from '../api';
import { loadKeys } from '../storage';
import { encryptForRecipient, decryptFromSender, base64ToBytes, bytesToBase64 } from '../crypto';
import { clearKeys } from '../storage';

interface ChatProps {
  onLogout: () => void;
}

export function Chat({ onLogout }: ChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [users, setUsers] = useState<Map<string, User>>(new Map());
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [currentUserId, setCurrentUserId] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [ws, setWs] = useState<WebSocket | null>(null);
  const wsInitializedRef = useRef(false);
  const dataLoadedRef = useRef(false);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  const keys = loadKeys();

  const loadMessages = useCallback(async () => {
    try {
      const msgs = await api.getMessages(100);
      setMessages(msgs);
      
      // Load any new user keys we don't have
      const stored = loadKeys();
      if (!stored) return;
      
      const userIds = new Set<string>();
      msgs.forEach(msg => {
        if (msg.sender_id !== stored.userId) userIds.add(msg.sender_id);
        if (msg.receiver_id !== stored.userId) userIds.add(msg.receiver_id);
      });
      
      if (userIds.size > 0) {
        setUsers(prevUsers => {
          const usersToFetch = Array.from(userIds).filter(id => !prevUsers.has(id));
          
          if (usersToFetch.length > 0) {
            Promise.all(
              usersToFetch.map(async userId => {
                try {
                  const response = await fetch(`/api/users/${userId}/keys`);
                  if (response.ok) {
                    const user = await response.json();
                    return { userId, user };
                  }
                } catch (err) {
                  console.error(`Failed to load user ${userId}:`, err);
                }
                return null;
              })
            ).then(results => {
              setUsers(currentUsers => {
                const newMap = new Map(currentUsers);
                results.forEach(result => {
                  if (result) {
                    newMap.set(result.userId, result.user);
                  }
                });
                return newMap;
              });
            });
          }
          
          return prevUsers;
        });
      }
    } catch (err) {
      console.error('Failed to load messages:', err);
    }
  }, []);

  // Initialize WebSocket connection
  useEffect(() => {
    if (wsInitializedRef.current) return;
    wsInitializedRef.current = true;

    const token = localStorage.getItem('token');
    if (!token) return;

    const websocket = new WebSocket(`ws://localhost:8000/ws?token=${token}`);
    
    websocket.onopen = () => {
      console.log('WebSocket connected');
      setWs(websocket);
      
      // Send ping every 30 seconds to keep connection alive
      const pingInterval = setInterval(() => {
        if (websocket.readyState === WebSocket.OPEN) {
          websocket.send('ping');
        }
      }, 30000);
      
      // Store interval ID to clear on close
      (websocket as any).pingInterval = pingInterval;
    };
    
    websocket.onmessage = (event) => {
      // Handle pong response (plain text)
      if (event.data === 'pong') {
        return;
      }
      
      // Handle JSON messages
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'new_message') {
          // Reload messages when notification received
          loadMessages();
        }
      } catch (err) {
        console.error('Failed to parse WebSocket message:', err);
      }
    };
    
    websocket.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
    
    websocket.onclose = () => {
      console.log('WebSocket disconnected');
      // Clear ping interval
      if ((websocket as any).pingInterval) {
        clearInterval((websocket as any).pingInterval);
      }
      setWs(null);
    };
    
    return () => {
      if ((websocket as any).pingInterval) {
        clearInterval((websocket as any).pingInterval);
      }
      if (websocket.readyState === WebSocket.OPEN || websocket.readyState === WebSocket.CONNECTING) {
        websocket.close();
      }
    };
  }, [loadMessages]);

  // Load initial data on mount
  useEffect(() => {
    if (dataLoadedRef.current) return;
    dataLoadedRef.current = true;
    loadData();
  }, [loadMessages]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadData = async () => {
    try {
      const stored = loadKeys();
      if (!stored || !stored.userId) return;

      setCurrentUserId(stored.userId);
      await loadMessages();
      setLoading(false);
    } catch (err) {
      if (err instanceof Error && (err.message.includes('401') || err.message.includes('403'))) {
        setError('Session expired. Please logout and login again.');
        return;
      }
      setError(err instanceof Error ? err.message : 'Failed to load data');
      setLoading(false);
    }
  };

  const searchUsers = async () => {
    if (!searchQuery.trim()) {
      setError('Please enter an Identity Public Key');
      return;
    }

    try {
      setError('');
      // Search for user by public key
      const user = await api.getUserByPublicKey(searchQuery.trim());
      
      // Check if it's not the current user
      if (user.user_id === currentUserId) {
        setError('Cannot message yourself!');
        return;
      }

      // Select this user to start conversation
      setSelectedUser(user);
      // Add user to the users Map so we can decrypt messages with them
      setUsers(prevUsers => {
        const newMap = new Map(prevUsers);
        newMap.set(user.user_id, user);
        return newMap;
      });
      setSearchQuery('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'User not found');
    }
  };

  const handleSendMessage = async () => {
    if (!newMessage.trim() || !selectedUser || !keys) return;

    try {
      const recipientEkPub = base64ToBytes(selectedUser.ek_pub);
      const plaintextToSend = newMessage; // Store before clearing

      const encrypted = encryptForRecipient(
        plaintextToSend,
        keys.ephemeral.privateKey,
        recipientEkPub,
        keys.identity.privateKey
      );

      const response = await api.sendMessage(
        selectedUser.user_id,
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.signature
      );

      // Store sent message plaintext locally (since we can't decrypt it later)
      const sentMessages = JSON.parse(localStorage.getItem('sentMessages') || '{}');
      sentMessages[response.message_id] = plaintextToSend;
      localStorage.setItem('sentMessages', JSON.stringify(sentMessages));

      setNewMessage('');
      // Reload messages immediately to show sent message
      await loadMessages();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send message');
    }
  };

  const decryptMessage = (msg: Message): string => {
    if (!keys) return '[Cannot decrypt - keys not loaded]';
    
    // If we sent this message, we can't decrypt it (encrypted for recipient)
    // Instead, retrieve the plaintext we stored locally
    if (msg.sender_id === currentUserId) {
      const sentMessages = JSON.parse(localStorage.getItem('sentMessages') || '{}');
      const plaintext = sentMessages[msg.message_id];
      if (plaintext) {
        return plaintext;
      }
      return '[Sent message - plaintext not stored locally]';
    }
    
    try {
      // Validate message fields
      if (!msg.ciphertext) return '[Missing ciphertext]';
      if (!msg.nonce) return '[Missing nonce]';
      if (!msg.signature) return '[Missing signature]';

      // This is a received message - decrypt using sender's keys
      const senderUser = users.get(msg.sender_id);
      
      if (!senderUser) {
        return '[Loading sender data...]';
      }

      if (!senderUser.ik_pub) return `[Missing ik_pub for sender]`;
      if (!senderUser.ek_pub) return `[Missing ek_pub for sender]`;

      const senderIkPub = base64ToBytes(senderUser.ik_pub);
      const senderEkPub = base64ToBytes(senderUser.ek_pub);

      return decryptFromSender(
        msg.ciphertext,
        msg.nonce,
        msg.signature,
        keys.ephemeral.privateKey,
        senderEkPub,
        senderIkPub
      );
    } catch (err) {
      console.error('Decryption error:', err);
      return `[Decryption failed: ${err instanceof Error ? err.message : 'Unknown error'}]`;
    }
  };

  const handleLogout = () => {
    if (confirm('Are you sure you want to logout? Make sure you have backed up your keys.')) {
      clearKeys();
      api.clearToken();
      onLogout();
    }
  };

  const getConversations = () => {
    const userMap = new Map<string, { user: User | null; lastMessage: Message }>();

    messages.forEach((msg) => {
      const otherUserId = msg.sender_id === currentUserId ? msg.receiver_id : msg.sender_id;
      
      if (!userMap.has(otherUserId) || new Date(msg.created_at) > new Date(userMap.get(otherUserId)!.lastMessage.created_at)) {
        userMap.set(otherUserId, {
          user: users.get(otherUserId) || null,
          lastMessage: msg,
        });
      }
    });

    return Array.from(userMap.values());
  };

  const getMessagesWithUser = (userId: string) => {
    return messages.filter(
      (msg) =>
        (msg.sender_id === currentUserId && msg.receiver_id === userId) ||
        (msg.sender_id === userId && msg.receiver_id === currentUserId)
    );
  };

  const conversations = getConversations();
  const currentMessages = selectedUser ? getMessagesWithUser(selectedUser.user_id) : [];
  
  useEffect(() => {
    if (!selectedUser) return;
    requestAnimationFrame(() => {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    });
  }, [selectedUser, currentMessages.length]);

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  return (
    <div className="app-container">
      <div className="user-search">
        <h3>🔍 Find Users</h3>
        <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
          <input
            type="text"
            className="input"
            placeholder="Enter user's Identity Public Key..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ marginBottom: 0 }}
          />
          <button className="button" onClick={searchUsers} style={{ width: 'auto', padding: '12px 20px' }}>
            Search
          </button>
        </div>
        
        {keys && (
          <div className="success" style={{ marginTop: '16px' }}>
            <strong>Your Identity Public Key:</strong><br />
            <code style={{ fontSize: '11px', wordBreak: 'break-all' }}>
              {bytesToBase64(keys.identity.publicKey)}
            </code>
            <br /><small>Share this with others so they can message you</small>
          </div>
        )}
      </div>

      <div className="chat-container">
        <div className="chat-header">
          <h2>💬 E2EE Messaging</h2>
          <button
            className="button button-secondary"
            onClick={handleLogout}
            style={{ width: 'auto', padding: '8px 16px' }}
          >
            Logout
          </button>
        </div>

        {error && <div className="error" style={{ margin: '12px' }}>{error}</div>}

        {!selectedUser ? (
          <div style={{ padding: '40px', textAlign: 'center', color: '#999' }}>
            {conversations.length === 0 ? (
              <>
                <h3>No conversations yet</h3>
                <p>Share your Identity Public Key above to start receiving messages!</p>
              </>
            ) : (
              <>
                <h3>Select a conversation</h3>
                <div className="user-list" style={{ marginTop: '20px' }}>
                  {conversations.map(({ user, lastMessage }) => (
                    <div
                      key={user?.user_id || lastMessage.sender_id}
                      className="user-item"
                      onClick={() => user && setSelectedUser(user)}
                    >
                      <div>
                        <strong>{user?.user_id?.slice(0, 8) || 'Unknown'}...</strong>
                        <div style={{ fontSize: '12px', opacity: 0.7 }}>
                          {new Date(lastMessage.created_at).toLocaleString()}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        ) : (
          <>
            <div style={{ padding: '12px', borderBottom: '1px solid #333', display: 'flex', alignItems: 'center', gap: '12px' }}>
              <button 
                className="button button-secondary" 
                onClick={() => setSelectedUser(null)}
                style={{ width: 'auto', padding: '8px 16px' }}
              >
                ← Back
              </button>
              <div>
                <strong>Chat with {selectedUser.user_id.slice(0, 8)}...</strong>
              </div>
            </div>
            <div className="chat-messages">
              {currentMessages.length === 0 ? (
                <div style={{ textAlign: 'center', color: '#999', padding: '40px' }}>
                  No messages yet. Start the conversation!
                </div>
              ) : (
                currentMessages.map((msg) => {
                  const isSent = msg.sender_id === currentUserId;
                  const decryptedText = decryptMessage(msg);
                  
                  return (
                    <div
                      key={msg.message_id}
                      className={`message ${isSent ? 'message-sent' : 'message-received'}`}
                    >
                      <div>{decryptedText}</div>
                      <div className="message-time">
                        {new Date(msg.created_at).toLocaleTimeString()}
                      </div>
                    </div>
                  );
                })
              )}
              <div ref={bottomRef} />
            </div>

            <div className="chat-input-container">
              <input
                type="text"
                className="chat-input"
                placeholder="Type a message..."
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
              />
              <button
                className="send-button"
                onClick={handleSendMessage}
                disabled={!newMessage.trim()}
              >
                Send
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
