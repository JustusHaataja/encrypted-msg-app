import { useState } from 'react';
import { api } from '../api';
import { generateIdentityKeyPair, generateEphemeralKeyPair, signMessage, bytesToBase64, type IdentityKeyPair, type EphemeralKeyPair } from '../crypto';
import { saveKeys } from '../storage';
import { base64ToBytes } from '../crypto';

interface RegisterProps {
  onSuccess: () => void;
  onSwitchToLogin: () => void;
}

export function Register({ onSuccess, onSwitchToLogin }: RegisterProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [keyPairs, setKeyPairs] = useState<{
    identity: IdentityKeyPair;
    ephemeral: EphemeralKeyPair;
  } | null>(null);

  const handleGenerateKeys = () => {
    const identity = generateIdentityKeyPair();
    const ephemeral = generateEphemeralKeyPair();
    
    setKeyPairs({ identity, ephemeral });
  };

  const handleRegister = async () => {
    if (!keyPairs) {
      setError('Please generate keys first');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // Use the generated keys
      const { identity, ephemeral } = keyPairs;

      // Register user
      const user = await api.registerUser(identity.publicKey, ephemeral.publicKey);

      // Request authentication challenge
      const { nonce } = await api.requestChallenge(user.user_id);

      // Sign the challenge
      const challengeBytes = base64ToBytes(nonce);
      const signature = signMessage(identity.privateKey, challengeBytes);

      // Verify and get token
      const { access_token } = await api.verifyChallenge(user.user_id, nonce, signature);
      api.setToken(access_token);

      // Save keys locally
      saveKeys(identity, ephemeral, user.user_id);

      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <h1>🔐 Create Account</h1>
      <p>Generate cryptographic keys for secure, end-to-end encrypted messaging.</p>

      {error && <div className="error">{error}</div>}

      <div className="warning">
        <strong>⚠️ Important:</strong> Your private keys will be stored in your browser.
        Don't lose access to this browser or you'll lose access to your account.
      </div>

      {keyPairs && (
        <div>
          <div className="key-display">
            <strong>Identity Public Key:</strong><br />
            {bytesToBase64(keyPairs.identity.publicKey)}
          </div>
          <div className="key-display">
            <strong>Ephemeral Public Key:</strong><br />
            {bytesToBase64(keyPairs.ephemeral.publicKey)}
          </div>
        </div>
      )}

      <button
        className="button"
        onClick={keyPairs ? handleRegister : handleGenerateKeys}
        disabled={loading}
      >
        {loading ? 'Creating Account...' : keyPairs ? 'Register Account' : 'Generate Keys'}
      </button>

      <div>
        <button
          className="button-secondary button"
          onClick={onSwitchToLogin}
          disabled={loading}
        >
          Already have keys? Login
        </button>
      </div>
    </div>
  );
}
