import { useState, useEffect, useReducer } from 'react';
import { Eye, EyeOff, Lock, Mail, User, Shield, Activity, Clock, AlertCircle, CheckCircle, XCircle } from 'lucide-react';

// Authentication State Management
const authReducer = (state, action) => {
  switch (action.type) {
    case 'LOGIN':
      return { ...state, user: action.payload, isAuthenticated: true };
    case 'LOGOUT':
      return { ...state, user: null, isAuthenticated: false, sessions: [] };
    case 'UPDATE_PROFILE':
      return { ...state, user: { ...state.user, ...action.payload } };
    case 'SET_SESSIONS':
      return { ...state, sessions: action.payload };
    case 'ADD_ACTIVITY':
      return { ...state, activities: [action.payload, ...state.activities].slice(0, 50) };
    default:
      return state;
  }
};

const initialAuthState = {
  user: null,
  isAuthenticated: false,
  sessions: [],
  activities: []
};

// Session Management Configuration
const SESSION_CONFIG = {
  MAX_CONCURRENT_SESSIONS_PER_USER: 3, // Max devices per user (0 = unlimited)
  MAX_TOTAL_ACTIVE_SESSIONS: 100, // Max total system sessions (0 = unlimited)
  SESSION_TIMEOUT_MINUTES: 30, // Auto-logout after inactivity
  ENFORCE_SINGLE_SESSION: false // Set true to allow only 1 device per user
};

// Global session storage (in production, use Redis or database)
const activeSessions = {};
const sessionsByUser = {}; // Track sessions per user

// Session Manager
class SessionManager {
  static createSession(userId, deviceInfo) {
    const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36);
    
    // Check total active sessions limit
    if (SESSION_CONFIG.MAX_TOTAL_ACTIVE_SESSIONS > 0) {
      const totalSessions = Object.keys(activeSessions).length;
      if (totalSessions >= SESSION_CONFIG.MAX_TOTAL_ACTIVE_SESSIONS) {
        throw new Error('Maximum system capacity reached. Please try again later.');
      }
    }
    
    // Check if single session enforcement is enabled
    if (SESSION_CONFIG.ENFORCE_SINGLE_SESSION) {
      // Revoke all existing sessions for this user
      this.revokeAllUserSessions(userId);
    }
    
    // Check concurrent sessions per user limit
    if (SESSION_CONFIG.MAX_CONCURRENT_SESSIONS_PER_USER > 0) {
      const userSessions = sessionsByUser[userId] || [];
      if (userSessions.length >= SESSION_CONFIG.MAX_CONCURRENT_SESSIONS_PER_USER) {
        // Remove oldest session
        const oldestSession = userSessions[0];
        this.revokeSession(oldestSession);
      }
    }
    
    // Create new session
    const session = {
      sessionId,
      userId,
      deviceInfo,
      createdAt: new Date(),
      lastActivity: new Date(),
      expiresAt: new Date(Date.now() + SESSION_CONFIG.SESSION_TIMEOUT_MINUTES * 60 * 1000)
    };
    
    activeSessions[sessionId] = session;
    
    if (!sessionsByUser[userId]) {
      sessionsByUser[userId] = [];
    }
    sessionsByUser[userId].push(sessionId);
    
    return session;
  }
  
  static validateSession(sessionId) {
    const session = activeSessions[sessionId];
    if (!session) return null;
    
    // Check if session expired
    if (new Date() > session.expiresAt) {
      this.revokeSession(sessionId);
      return null;
    }
    
    // Update last activity and extend expiration
    session.lastActivity = new Date();
    session.expiresAt = new Date(Date.now() + SESSION_CONFIG.SESSION_TIMEOUT_MINUTES * 60 * 1000);
    
    return session;
  }
  
  static revokeSession(sessionId) {
    const session = activeSessions[sessionId];
    if (!session) return;
    
    delete activeSessions[sessionId];
    
    // Remove from user's session list
    if (sessionsByUser[session.userId]) {
      sessionsByUser[session.userId] = sessionsByUser[session.userId].filter(id => id !== sessionId);
    }
  }
  
  static revokeAllUserSessions(userId) {
    const userSessions = sessionsByUser[userId] || [];
    userSessions.forEach(sessionId => {
      delete activeSessions[sessionId];
    });
    sessionsByUser[userId] = [];
  }
  
  static getUserSessions(userId) {
    const userSessionIds = sessionsByUser[userId] || [];
    return userSessionIds.map(id => activeSessions[id]).filter(Boolean);
  }
  
  static getActiveSessionsCount() {
    return Object.keys(activeSessions).length;
  }
  
  static getSessionStats() {
    const totalSessions = this.getActiveSessionsCount();
    const uniqueUsers = Object.keys(sessionsByUser).filter(userId => 
      sessionsByUser[userId].length > 0
    ).length;
    
    return {
      totalActiveSessions: totalSessions,
      uniqueActiveUsers: uniqueUsers,
      maxCapacity: SESSION_CONFIG.MAX_TOTAL_ACTIVE_SESSIONS || 'Unlimited',
      utilizationPercent: SESSION_CONFIG.MAX_TOTAL_ACTIVE_SESSIONS > 0 
        ? Math.round((totalSessions / SESSION_CONFIG.MAX_TOTAL_ACTIVE_SESSIONS) * 100)
        : 0
    };
  }
}

// Simulated user database (for demo only - replace with real backend)
const mockUsers = {
  'admin@example.com': {
    password: 'Admin@123',
    user: {
      id: '1',
      email: 'admin@example.com',
      name: 'Admin User',
      role: 'admin',
      twoFactorEnabled: false
    }
  },
  'user@example.com': {
    password: 'User@123',
    user: {
      id: '2',
      email: 'user@example.com',
      name: 'Regular User',
      role: 'user',
      twoFactorEnabled: false
    }
  },
  'moderator@example.com': {
    password: 'Mod@123',
    user: {
      id: '3',
      email: 'moderator@example.com',
      name: 'Moderator',
      role: 'moderator',
      twoFactorEnabled: true
    }
  }
};

// Simulated API calls (replace with real backend)
const api = {
  async register(data) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    // Check if user already exists
    if (mockUsers[data.email]) {
      throw new Error('User already exists');
    }
    // In real app, save to database
    mockUsers[data.email] = {
      password: data.password,
      user: {
        id: Date.now().toString(),
        email: data.email,
        name: data.name,
        role: 'user',
        twoFactorEnabled: false
      }
    };
    return { success: true, message: 'Verification email sent to ' + data.email };
  },
  async verifyEmail(token) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    return { success: true, message: 'Email verified successfully' };
  },
  async login(credentials) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Check if user exists
    const userRecord = mockUsers[credentials.email];
    if (!userRecord) {
      throw new Error('User not found');
    }
    
    // Check password
    if (userRecord.password !== credentials.password) {
      throw new Error('Invalid password');
    }
    
    return {
      success: true,
      user: userRecord.user,
      accessToken: 'mock-access-token-' + Date.now(),
      refreshToken: 'mock-refresh-token-' + Date.now()
    };
  },
  async verify2FA(code) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    return { success: true };
  },
  async resetPassword(email) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    return { success: true, message: 'Password reset email sent' };
  },
  async updateProfile(data) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    return { success: true, user: data };
  },
  async getSessions() {
    return [
      { id: '1', device: 'Chrome on Windows', location: 'New York, US', lastActive: new Date(), current: true },
      { id: '2', device: 'Safari on iPhone', location: 'San Francisco, US', lastActive: new Date(Date.now() - 86400000), current: false }
    ];
  },
  async revokeSession(sessionId) {
    await new Promise(resolve => setTimeout(resolve, 500));
    return { success: true };
  }
};

// Rate Limiter
class RateLimiter {
  constructor(maxAttempts, windowMs) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.attempts = {};
  }

  isAllowed(key) {
    const now = Date.now();
    if (!this.attempts[key]) {
      this.attempts[key] = [];
    }
    this.attempts[key] = this.attempts[key].filter(time => now - time < this.windowMs);
    if (this.attempts[key].length >= this.maxAttempts) {
      return false;
    }
    this.attempts[key].push(now);
    return true;
  }

  getRetryAfter(key) {
    if (!this.attempts[key] || this.attempts[key].length === 0) return 0;
    const oldestAttempt = Math.min(...this.attempts[key]);
    return Math.max(0, this.windowMs - (Date.now() - oldestAttempt));
  }
}

const loginRateLimiter = new RateLimiter(5, 15 * 60 * 1000); // 5 attempts per 15 minutes

// Main Component
export default function AuthSystem() {
  const [authState, dispatch] = useReducer(authReducer, initialAuthState);
  const [view, setView] = useState('login');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [twoFactorRequired, setTwoFactorRequired] = useState(false);
  const [tempCredentials, setTempCredentials] = useState(null);

  useEffect(() => {
    if (authState.isAuthenticated) {
      loadSessions();
    }
  }, [authState.isAuthenticated]);

  const loadSessions = async () => {
    const sessions = await api.getSessions();
    dispatch({ type: 'SET_SESSIONS', payload: sessions });
  };

  const addActivity = (action, details) => {
    dispatch({
      type: 'ADD_ACTIVITY',
      payload: {
        id: Date.now().toString(),
        action,
        details,
        timestamp: new Date(),
        ip: '192.168.1.1'
      }
    });
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    const formData = new FormData(e.target);
    const email = formData.get('email');
    const password = formData.get('password');

    if (!loginRateLimiter.isAllowed(email)) {
      const retryAfter = Math.ceil(loginRateLimiter.getRetryAfter(email) / 1000 / 60);
      setError(`Too many login attempts. Please try again in ${retryAfter} minutes.`);
      addActivity('Failed Login', 'Rate limit exceeded');
      return;
    }

    setLoading(true);
    try {
      const result = await api.login({ email, password });
      if (result.success) {
        if (result.user.twoFactorEnabled) {
          setTwoFactorRequired(true);
          setTempCredentials(result);
          addActivity('2FA Required', email);
        } else {
          dispatch({ type: 'LOGIN', payload: result.user });
          addActivity('Login Success', email);
          setSuccess('Login successful!');
        }
      }
    } catch (err) {
      setError('Invalid credentials. Please try again.');
      addActivity('Failed Login', email);
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    const formData = new FormData(e.target);
    const data = {
      name: formData.get('name'),
      email: formData.get('email'),
      password: formData.get('password'),
      confirmPassword: formData.get('confirmPassword')
    };

    if (data.password !== data.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    if (data.password.length < 8) {
      setError('Password must be at least 8 characters');
      setLoading(false);
      return;
    }

    try {
      const result = await api.register(data);
      setSuccess(result.message);
      addActivity('Registration', data.email);
      setTimeout(() => setView('login'), 3000);
    } catch (err) {
      setError('Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handle2FAVerification = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const formData = new FormData(e.target);
    const code = formData.get('code');

    try {
      const result = await api.verify2FA(code);
      if (result.success && tempCredentials) {
        dispatch({ type: 'LOGIN', payload: tempCredentials.user });
        addActivity('2FA Success', tempCredentials.user.email);
        setSuccess('Login successful!');
        setTwoFactorRequired(false);
        setTempCredentials(null);
      }
    } catch (err) {
      setError('Invalid 2FA code. Please try again.');
      addActivity('2FA Failed', tempCredentials?.user?.email);
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordReset = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    const formData = new FormData(e.target);
    const email = formData.get('email');

    try {
      const result = await api.resetPassword(email);
      setSuccess(result.message);
      addActivity('Password Reset Request', email);
    } catch (err) {
      setError('Failed to send reset email. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    addActivity('Logout', authState.user?.email);
    dispatch({ type: 'LOGOUT' });
    setView('login');
    setSuccess('Logged out successfully');
  };

  const handleRevokeSession = async (sessionId) => {
    try {
      await api.revokeSession(sessionId);
      const sessions = authState.sessions.filter(s => s.id !== sessionId);
      dispatch({ type: 'SET_SESSIONS', payload: sessions });
      addActivity('Session Revoked', `Session ${sessionId}`);
      setSuccess('Session revoked successfully');
    } catch (err) {
      setError('Failed to revoke session');
    }
  };

  if (twoFactorRequired) {
    return <TwoFactorForm onSubmit={handle2FAVerification} loading={loading} error={error} />;
  }

  if (authState.isAuthenticated) {
    return (
      <Dashboard
        user={authState.user}
        sessions={authState.sessions}
        activities={authState.activities}
        onLogout={handleLogout}
        onRevokeSession={handleRevokeSession}
        dispatch={dispatch}
        addActivity={addActivity}
        error={error}
        success={success}
        setError={setError}
        setSuccess={setSuccess}
      />
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {error && <AlertMessage type="error" message={error} onClose={() => setError('')} />}
        {success && <AlertMessage type="success" message={success} onClose={() => setSuccess('')} />}

        <div className="bg-white rounded-2xl shadow-xl p-8">
          <div className="flex justify-center mb-8">
            <div className="bg-indigo-600 p-3 rounded-full">
              <Shield className="w-8 h-8 text-white" />
            </div>
          </div>

          <h1 className="text-3xl font-bold text-center text-gray-800 mb-2">
            {view === 'login' ? 'Welcome Back' : view === 'register' ? 'Create Account' : 'Reset Password'}
          </h1>
          <p className="text-center text-gray-600 mb-8">
            {view === 'login' ? 'Sign in to your account' : view === 'register' ? 'Sign up for a new account' : 'Enter your email to reset password'}
          </p>

          {view === 'login' && <LoginForm onSubmit={handleLogin} loading={loading} />}
          {view === 'register' && <RegisterForm onSubmit={handleRegister} loading={loading} />}
          {view === 'reset' && <ResetPasswordForm onSubmit={handlePasswordReset} loading={loading} />}

          <div className="mt-6 text-center">
            {view === 'login' && (
              <>
                <button
                  onClick={() => setView('reset')}
                  className="text-sm text-indigo-600 hover:text-indigo-800 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 rounded"
                >
                  Forgot password?
                </button>
                <p className="mt-4 text-sm text-gray-600">
                  Don't have an account?{' '}
                  <button
                    onClick={() => setView('register')}
                    className="text-indigo-600 hover:text-indigo-800 font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 rounded"
                  >
                    Sign up
                  </button>
                </p>
              </>
            )}
            {(view === 'register' || view === 'reset') && (
              <button
                onClick={() => setView('login')}
                className="text-sm text-indigo-600 hover:text-indigo-800 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 rounded"
              >
                Back to login
              </button>
            )}
          </div>
        </div>

        <p className="mt-8 text-center text-sm text-gray-600">
          Protected by rate limiting and brute force protection
        </p>
      </div>
    </div>
  );
}

// Login Form Component
function LoginForm({ onSubmit, loading }) {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <form onSubmit={onSubmit} className="space-y-6">
      <div>
        <label htmlFor="login-email" className="block text-sm font-medium text-gray-700 mb-2">
          Email Address
        </label>
        <div className="relative">
          <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" aria-hidden="true" />
          <input
            type="email"
            id="login-email"
            name="email"
            required
            autoComplete="email"
            className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            placeholder="you@example.com"
            aria-required="true"
          />
        </div>
      </div>

      <div>
        <label htmlFor="login-password" className="block text-sm font-medium text-gray-700 mb-2">
          Password
        </label>
        <div className="relative">
          <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" aria-hidden="true" />
          <input
            type={showPassword ? 'text' : 'password'}
            id="login-password"
            name="password"
            required
            autoComplete="current-password"
            className="w-full pl-10 pr-12 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            placeholder="••••••••"
            aria-required="true"
          />
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 focus:outline-none focus:ring-2 focus:ring-indigo-500 rounded"
            aria-label={showPassword ? 'Hide password' : 'Show password'}
          >
            {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
          </button>
        </div>
      </div>

      <button
        type="submit"
        disabled={loading}
        className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        aria-busy={loading}
      >
        {loading ? 'Signing in...' : 'Sign In'}
      </button>
    </form>
  );
}

// Register Form Component
function RegisterForm({ onSubmit, loading }) {
  const [showPassword, setShowPassword] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState(0);

  const checkPasswordStrength = (password) => {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;
    setPasswordStrength(strength);
  };

  return (
    <form onSubmit={onSubmit} className="space-y-6">
      <div>
        <label htmlFor="register-name" className="block text-sm font-medium text-gray-700 mb-2">
          Full Name
        </label>
        <div className="relative">
          <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" aria-hidden="true" />
          <input
            type="text"
            id="register-name"
            name="name"
            required
            autoComplete="name"
            className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            placeholder="John Doe"
            aria-required="true"
          />
        </div>
      </div>

      <div>
        <label htmlFor="register-email" className="block text-sm font-medium text-gray-700 mb-2">
          Email Address
        </label>
        <div className="relative">
          <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" aria-hidden="true" />
          <input
            type="email"
            id="register-email"
            name="email"
            required
            autoComplete="email"
            className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            placeholder="you@example.com"
            aria-required="true"
          />
        </div>
      </div>

      <div>
        <label htmlFor="register-password" className="block text-sm font-medium text-gray-700 mb-2">
          Password
        </label>
        <div className="relative">
          <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" aria-hidden="true" />
          <input
            type={showPassword ? 'text' : 'password'}
            id="register-password"
            name="password"
            required
            autoComplete="new-password"
            onChange={(e) => checkPasswordStrength(e.target.value)}
            className="w-full pl-10 pr-12 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            placeholder="••••••••"
            aria-required="true"
            aria-describedby="password-strength"
          />
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 focus:outline-none focus:ring-2 focus:ring-indigo-500 rounded"
            aria-label={showPassword ? 'Hide password' : 'Show password'}
          >
            {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
          </button>
        </div>
        <div id="password-strength" className="mt-2">
          <div className="flex gap-1">
            {[...Array(5)].map((_, i) => (
              <div
                key={i}
                className={`h-1 flex-1 rounded ${
                  i < passwordStrength
                    ? passwordStrength <= 2
                      ? 'bg-red-500'
                      : passwordStrength <= 3
                      ? 'bg-yellow-500'
                      : 'bg-green-500'
                    : 'bg-gray-200'
                }`}
                role="presentation"
              />
            ))}
          </div>
          <p className="text-xs text-gray-600 mt-1">
            {passwordStrength === 0 && 'Enter a password'}
            {passwordStrength === 1 && 'Weak password'}
            {passwordStrength === 2 && 'Fair password'}
            {passwordStrength === 3 && 'Good password'}
            {passwordStrength === 4 && 'Strong password'}
            {passwordStrength === 5 && 'Very strong password'}
          </p>
        </div>
      </div>

      <div>
        <label htmlFor="register-confirm-password" className="block text-sm font-medium text-gray-700 mb-2">
          Confirm Password
        </label>
        <div className="relative">
          <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" aria-hidden="true" />
          <input
            type={showPassword ? 'text' : 'password'}
            id="register-confirm-password"
            name="confirmPassword"
            required
            autoComplete="new-password"
            className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            placeholder="••••••••"
            aria-required="true"
          />
        </div>
      </div>

      <button
        type="submit"
        disabled={loading}
        className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        aria-busy={loading}
      >
        {loading ? 'Creating Account...' : 'Create Account'}
      </button>
    </form>
  );
}

// Reset Password Form
function ResetPasswordForm({ onSubmit, loading }) {
  return (
    <form onSubmit={onSubmit} className="space-y-6">
      <div>
        <label htmlFor="reset-email" className="block text-sm font-medium text-gray-700 mb-2">
          Email Address
        </label>
        <div className="relative">
          <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" aria-hidden="true" />
          <input
            type="email"
            id="reset-email"
            name="email"
            required
            autoComplete="email"
            className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            placeholder="you@example.com"
            aria-required="true"
          />
        </div>
      </div>

      <button
        type="submit"
        disabled={loading}
        className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        aria-busy={loading}
      >
        {loading ? 'Sending...' : 'Send Reset Link'}
      </button>
    </form>
  );
}

// Two Factor Form
function TwoFactorForm({ onSubmit, loading, error }) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {error && <AlertMessage type="error" message={error} />}
        <div className="bg-white rounded-2xl shadow-xl p-8">
          <div className="flex justify-center mb-8">
            <div className="bg-indigo-600 p-3 rounded-full">
              <Shield className="w-8 h-8 text-white" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-center text-gray-800 mb-2">Two-Factor Authentication</h1>
          <p className="text-center text-gray-600 mb-8">Enter the 6-digit code from your authenticator app</p>
          <form onSubmit={onSubmit} className="space-y-6">
            <div>
              <label htmlFor="2fa-code" className="block text-sm font-medium text-gray-700 mb-2">
                Authentication Code
              </label>
              <input
                type="text"
                id="2fa-code"
                name="code"
                required
                maxLength="6"
                pattern="[0-9]{6}"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg text-center text-2xl tracking-widest focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                placeholder="000000"
                aria-required="true"
                autoComplete="one-time-code"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              aria-busy={loading}
            >
              {loading ? 'Verifying...' : 'Verify'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

// Dashboard Component
function Dashboard({ user, sessions, activities, onLogout, onRevokeSession, error, success, setError, setSuccess }) {
  const [activeTab, setActiveTab] = useState('profile');

  const getRoleBadgeColor = (role) => {
    switch (role) {
      case 'admin': return 'bg-red-100 text-red-800';
      case 'moderator': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-blue-100 text-blue-800';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-3">
              <div className="bg-indigo-600 p-2 rounded-lg">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <h1 className="text-xl font-bold text-gray-900">Prixgen Techonology</h1>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-sm text-gray-700">{user.name}</span>
              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getRoleBadgeColor(user.role)}`}>
                {user.role.toUpperCase()}
              </span>
              <button
                onClick={onLogout}
                className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition-colors"
                aria-label="Logout"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && <AlertMessage type="error" message={error} onClose={() => setError('')} />}
        {success && <AlertMessage type="success" message={success} onClose={() => setSuccess('')} />}

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          <div className="border-b border-gray-200">
            <nav className="flex" role="tablist">
              {['profile', 'sessions', 'activity', 'security'].map((tab) => (
                <button
                  key={tab}
                  role="tab"
                  aria-selected={activeTab === tab}
                  aria-controls={`${tab}-panel`}
                  onClick={() => setActiveTab(tab)}
                  className={`px-6 py-4 font-medium text-sm focus:outline-none focus:ring-2 focus:ring-inset focus:ring-indigo-500 ${
                    activeTab === tab
                      ? 'border-b-2 border-indigo-600 text-indigo-600'
                      : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  {tab.charAt(0).toUpperCase() + tab.slice(1)}
                </button>
              ))}
            </nav>
          </div>

          <div className="p-6">
            {activeTab === 'profile' && <ProfileTab user={user} />}
            {activeTab === 'sessions' && <SessionsTab sessions={sessions} onRevoke={onRevokeSession} />}
            {activeTab === 'activity' && <ActivityTab activities={activities} />}
            {activeTab === 'security' && <SecurityTab user={user} />}
          </div>
        </div>
      </div>
    </div>
  );
}

// Profile Tab
function ProfileTab({ user }) {
  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState({
    name: user.name,
    email: user.email,
    phone: '+1 (555) 123-4567',
    bio: 'Software developer with a passion for security'
  });

  const handleSave = async () => {
    await api.updateProfile(formData);
    setIsEditing(false);
  };

  return (
    <div className="space-y-6" role="tabpanel" id="profile-panel">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-gray-900">Profile Information</h2>
        <button
          onClick={() => isEditing ? handleSave() : setIsEditing(true)}
          className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
        >
          {isEditing ? 'Save Changes' : 'Edit Profile'}
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label htmlFor="profile-name" className="block text-sm font-medium text-gray-700 mb-2">
            Full Name
          </label>
          <input
            type="text"
            id="profile-name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            disabled={!isEditing}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500"
          />
        </div>

        <div>
          <label htmlFor="profile-email" className="block text-sm font-medium text-gray-700 mb-2">
            Email Address
          </label>
          <input
            type="email"
            id="profile-email"
            value={formData.email}
            onChange={(e) => setFormData({ ...formData, email: e.target.value })}
            disabled={!isEditing}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500"
          />
        </div>

        <div>
          <label htmlFor="profile-phone" className="block text-sm font-medium text-gray-700 mb-2">
            Phone Number
          </label>
          <input
            type="tel"
            id="profile-phone"
            value={formData.phone}
            onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
            disabled={!isEditing}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Role
          </label>
          <input
            type="text"
            value={user.role.toUpperCase()}
            disabled
            className="w-full px-4 py-2 border border-gray-300 rounded-lg bg-gray-50 text-gray-500"
          />
        </div>

        <div className="md:col-span-2">
          <label htmlFor="profile-bio" className="block text-sm font-medium text-gray-700 mb-2">
            Bio
          </label>
          <textarea
            id="profile-bio"
            rows="4"
            value={formData.bio}
            onChange={(e) => setFormData({ ...formData, bio: e.target.value })}
            disabled={!isEditing}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent disabled:bg-gray-50 disabled:text-gray-500"
          />
        </div>
      </div>
    </div>
  );
}

// Sessions Tab
function SessionsTab({ sessions, onRevoke }) {
  return (
    <div className="space-y-6" role="tabpanel" id="sessions-panel">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Active Sessions</h2>
        <p className="text-gray-600">Manage your active sessions across different devices</p>
      </div>

      <div className="space-y-4">
        {sessions.map((session) => (
          <div key={session.id} className="border border-gray-200 rounded-lg p-4 hover:border-gray-300 transition-colors">
            <div className="flex justify-between items-start">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <h3 className="font-semibold text-gray-900">{session.device}</h3>
                  {session.current && (
                    <span className="px-2 py-1 bg-green-100 text-green-800 text-xs font-medium rounded">
                      Current Session
                    </span>
                  )}
                </div>
                <div className="space-y-1 text-sm text-gray-600">
                  <p className="flex items-center gap-2">
                    <Clock className="w-4 h-4" aria-hidden="true" />
                    Last active: {session.lastActive.toLocaleString()}
                  </p>
                  <p>Location: {session.location}</p>
                </div>
              </div>
              {!session.current && (
                <button
                  onClick={() => onRevoke(session.id)}
                  className="px-3 py-1 text-sm text-red-600 hover:bg-red-50 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
                  aria-label={`Revoke session on ${session.device}`}
                >
                  Revoke
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Activity Tab
function ActivityTab({ activities }) {
  return (
    <div className="space-y-6" role="tabpanel" id="activity-panel">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Activity Log</h2>
        <p className="text-gray-600">Recent activity on your account</p>
      </div>

      <div className="space-y-3">
        {activities.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Activity className="w-12 h-12 mx-auto mb-3 text-gray-400" aria-hidden="true" />
            <p>No activity recorded yet</p>
          </div>
        ) : (
          activities.map((activity) => (
            <div key={activity.id} className="border border-gray-200 rounded-lg p-4 hover:border-gray-300 transition-colors">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="font-semibold text-gray-900">{activity.action}</h3>
                  <p className="text-sm text-gray-600 mt-1">{activity.details}</p>
                  <p className="text-xs text-gray-500 mt-2">IP: {activity.ip}</p>
                </div>
                <div className="text-right text-sm text-gray-500">
                  <p>{activity.timestamp.toLocaleTimeString()}</p>
                  <p>{activity.timestamp.toLocaleDateString()}</p>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// Security Tab
function SecurityTab({ user }) {
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(user.twoFactorEnabled);
  const [showQRCode, setShowQRCode] = useState(false);

  const toggle2FA = () => {
    if (!twoFactorEnabled) {
      setShowQRCode(true);
    } else {
      setTwoFactorEnabled(false);
    }
  };

  const confirm2FASetup = () => {
    setTwoFactorEnabled(true);
    setShowQRCode(false);
  };

  return (
    <div className="space-y-6" role="tabpanel" id="security-panel">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Settings</h2>
        <p className="text-gray-600">Manage your account security preferences</p>
      </div>

      <div className="space-y-6">
        <div className="border border-gray-200 rounded-lg p-6">
          <div className="flex justify-between items-start">
            <div>
              <h3 className="font-semibold text-gray-900 mb-2">Two-Factor Authentication</h3>
              <p className="text-sm text-gray-600">
                Add an extra layer of security to your account by requiring a verification code
              </p>
            </div>
            <button
              onClick={toggle2FA}
              className={`px-4 py-2 rounded-lg font-medium focus:outline-none focus:ring-2 focus:ring-offset-2 ${
                twoFactorEnabled
                  ? 'bg-red-100 text-red-700 hover:bg-red-200 focus:ring-red-500'
                  : 'bg-green-100 text-green-700 hover:bg-green-200 focus:ring-green-500'
              }`}
              aria-pressed={twoFactorEnabled}
            >
              {twoFactorEnabled ? 'Disable' : 'Enable'}
            </button>
          </div>

          {showQRCode && (
            <div className="mt-6 p-4 bg-gray-50 rounded-lg">
              <h4 className="font-medium text-gray-900 mb-3">Setup Two-Factor Authentication</h4>
              <ol className="text-sm text-gray-600 space-y-2 mb-4 list-decimal list-inside">
                <li>Install an authenticator app like Google Authenticator or Authy</li>
                <li>Scan the QR code below or enter the setup key manually</li>
                <li>Enter the 6-digit code from your app to confirm</li>
              </ol>
              <div className="bg-white p-4 rounded-lg border border-gray-300 inline-block">
                <div className="w-48 h-48 bg-gray-200 flex items-center justify-center">
                  <p className="text-sm text-gray-500 text-center">QR Code<br/>Placeholder</p>
                </div>
              </div>
              <p className="text-sm text-gray-600 mt-3">
                Setup Key: <code className="bg-white px-2 py-1 rounded border border-gray-300 font-mono">JBSWY3DPEHPK3PXP</code>
              </p>
              <div className="mt-4">
                <input
                  type="text"
                  placeholder="Enter 6-digit code"
                  maxLength="6"
                  className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  aria-label="Enter verification code"
                />
                <button
                  onClick={confirm2FASetup}
                  className="ml-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
                >
                  Confirm
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="border border-gray-200 rounded-lg p-6">
          <h3 className="font-semibold text-gray-900 mb-2">Change Password</h3>
          <p className="text-sm text-gray-600 mb-4">Update your password regularly to keep your account secure</p>
          <button className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2">
            Change Password
          </button>
        </div>

        <div className="border border-gray-200 rounded-lg p-6">
          <h3 className="font-semibold text-gray-900 mb-2">Trusted Devices</h3>
          <p className="text-sm text-gray-600 mb-4">Devices you've marked as trusted won't require 2FA</p>
          <button className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2">
            Manage Devices
          </button>
        </div>

        <div className="border border-red-200 rounded-lg p-6 bg-red-50">
          <h3 className="font-semibold text-red-900 mb-2">Danger Zone</h3>
          <p className="text-sm text-red-700 mb-4">Permanently delete your account and all associated data</p>
          <button className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2">
            Delete Account
          </button>
        </div>
      </div>
    </div>
  );
}

// Alert Message Component
function AlertMessage({ type, message, onClose }) {
  const isError = type === 'error';
  const Icon = isError ? XCircle : CheckCircle;
  
  return (
    <div
      className={`mb-6 p-4 rounded-lg flex items-start gap-3 ${
        isError ? 'bg-red-50 border border-red-200' : 'bg-green-50 border border-green-200'
      }`}
      role="alert"
      aria-live="polite"
    >
      <Icon className={`w-5 h-5 flex-shrink-0 ${isError ? 'text-red-600' : 'text-green-600'}`} aria-hidden="true" />
      <div className="flex-1">
        <p className={`text-sm font-medium ${isError ? 'text-red-800' : 'text-green-800'}`}>
          {message}
        </p>
      </div>
      {onClose && (
        <button
          onClick={onClose}
          className={`flex-shrink-0 ${isError ? 'text-red-600 hover:text-red-800' : 'text-green-600 hover:text-green-800'} focus:outline-none focus:ring-2 focus:ring-offset-2 ${isError ? 'focus:ring-red-500' : 'focus:ring-green-500'} rounded`}
          aria-label="Close alert"
        >
          <XCircle className="w-5 h-5" />
        </button>
      )}
    </div>
  );
}