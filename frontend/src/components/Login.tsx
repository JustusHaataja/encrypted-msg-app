import { useState, useEffect, useRef } from 'react';
import { api } from '../api';
import { signMessage, base64ToBytes } from '../crypto';
import { loadKeys } from '../storage';

interface LoginProps {
  onSuccess: () => void;
  onSwitchToRegister: () => void;
}

export function Login({ onSuccess, onSwitchToRegister }: LoginProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const loginAttemptedRef = useRef(false);

  // Auto-login on component mount
  useEffect(() => {
    if (!loginAttemptedRef.current) {
      loginAttemptedRef.current = true;
      handleLogin();
    }
  }, []);

  const handleLogin = async () => {
    if (loading) return; // Prevent concurrent login attempts
    
    setLoading(true);
    setError('');

    try {
      // Load keys from storage
      const stored = loadKeys();
      if (!stored || !stored.userId) {
        setError('No keys found. Please register first.');
        setLoading(false);
        return;
      }

      // Clear any old token before requesting new challenge
      api.clearToken();

      // Request fresh challenge
      const { nonce } = await api.requestChallenge(stored.userId);

      // Sign challenge
      const challengeBytes = base64ToBytes(nonce);
      const signature = signMessage(stored.identity.privateKey, challengeBytes);

      // Verify and get token
      const { access_token } = await api.verifyChallenge(
        stored.userId,
        nonce,
        signature
      );
      api.setToken(access_token);

      onSuccess();
    } catch (err) {
      console.error('Login error:', err);
      setError(err instanceof Error ? err.message : 'Login failed');
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <h1>🔓 {loading ? 'Signing In...' : 'Login'}</h1>
      <p>{loading ? 'Authenticating with your keys...' : 'Sign in using your stored cryptographic keys.'}</p>

      {error && <div className="error">{error}</div>}

      {!loading && !error && (
        <div className="success" style={{ marginBottom: '20px' }}>
          <strong>✓ Keys found in browser storage</strong><br />
          Automatic sign-in in progress...
        </div>
      )}

      {error && (
        <button
          className="button"
          onClick={handleLogin}
          disabled={loading}
        >
          {loading ? 'Authenticating...' : 'Retry Login'}
        </button>
      )}

      <div style={{ marginTop: '20px', textAlign: 'center' }}>
        <button
          className="button-secondary button"
          onClick={onSwitchToRegister}
          disabled={loading}
        >
          Need new keys? Register
        </button>
      </div>
    </div>
  );
}
