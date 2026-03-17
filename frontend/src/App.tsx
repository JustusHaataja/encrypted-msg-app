import { useState, useEffect } from 'react';
import { Register } from './components/Register';
import { Login } from './components/Login';
import { Chat } from './components/Chat';
import { hasKeys } from './storage';
import './styles.css';

type Screen = 'loading' | 'register' | 'login' | 'chat';

function App() {
  const [screen, setScreen] = useState<Screen>('loading');

  useEffect(() => {
    // Check if user has keys stored
    const keysExist = hasKeys();
    setScreen(keysExist ? 'login' : 'register');
  }, []);

  if (screen === 'loading') {
    return <div className="loading">Loading...</div>;
  }

  if (screen === 'register') {
    return (
      <Register
        onSuccess={() => setScreen('chat')}
        onSwitchToLogin={() => setScreen('login')}
      />
    );
  }

  if (screen === 'login') {
    return (
      <Login
        onSuccess={() => setScreen('chat')}
        onSwitchToRegister={() => setScreen('register')}
      />
    );
  }

  return <Chat onLogout={() => setScreen('register')} />;
}

export default App;
