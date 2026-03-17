/**
 * API client for communicating with the E2EE messaging backend.
 * Handles all HTTP requests to the server.
 */
import { bytesToBase64 } from './crypto';

const API_BASE = '/api';

// Type definitions matching backend schemas
export interface User {
  user_id: string;
  ik_pub: string;
  ek_pub: string;
  created_at: string;
}

export interface Message {
  message_id: string;
  sender_id: string;
  receiver_id: string;
  ciphertext: string;
  nonce: string;
  signature: string;
  created_at: string;
  expires_at?: string;
}

export interface ChallengeResponse {
  nonce: string;
  expires_in: number;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

class ApiClient {
  private token: string | null = null;

  constructor() {
    // Restore token from localStorage on initialization
    this.token = localStorage.getItem('token');
  }

  setToken(token: string) {
    this.token = token;
    localStorage.setItem('token', token);
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem('token');
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(error.detail || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Health check
  async healthCheck(): Promise<{ status: string }> {
    return this.request('/health');
  }

  // User registration
  async registerUser(ikPub: Uint8Array, ekPub: Uint8Array): Promise<User> {
    return this.request('/users/register', {
      method: 'POST',
      body: JSON.stringify({
        ik_pub: bytesToBase64(ikPub),
        ek_pub: bytesToBase64(ekPub),
      }),
    });
  }

  // Get user by public key
  async getUserByPublicKey(ikPub: string): Promise<User> {
    return this.request(`/users/pubkey/${encodeURIComponent(ikPub)}`);
  }

  // Authentication challenge
  async requestChallenge(userId: string): Promise<ChallengeResponse> {
    return this.request('/auth/challenge', {
      method: 'POST',
      body: JSON.stringify({
        user_id: userId,
      }),
    });
  }

  // Verify challenge and get token
  async verifyChallenge(
    userId: string,
    nonce: string,
    signature: Uint8Array
  ): Promise<TokenResponse> {
    return this.request('/auth/verify', {
      method: 'POST',
      body: JSON.stringify({
        user_id: userId,
        nonce: nonce,
        signature: bytesToBase64(signature),
      }),
    });
  }

  // Send encrypted message
  async sendMessage(
    receiverId: string,
    ciphertext: string,
    nonce: string,
    signature: string,
    expiresInMinutes: number = 60
  ): Promise<Message> {
    // Calculate expiration timestamp
    const expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000).toISOString();
    
    return this.request('/messages', {
      method: 'POST',
      body: JSON.stringify({
        receiver_id: receiverId,
        ciphertext,
        nonce,
        signature,
        expires_at: expiresAt,
      }),
    });
  }

  // Get messages for authenticated user
  async getMessages(limit: number = 50): Promise<Message[]> {
    return this.request(`/messages?limit=${limit}`);
  }

  // Get specific message
  async getMessage(messageId: string): Promise<Message> {
    return this.request(`/messages/${messageId}`);
  }
}

export const api = new ApiClient();
