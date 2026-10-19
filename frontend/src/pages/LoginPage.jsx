// Kirim autentikasi melalui AuthContext dan tampilkan status pengiriman formulir.
import React, { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { Shield, User, Lock, AlertCircle, Loader2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { login, isAuthenticated, loading } = useAuth();
  const navigate = useNavigate();

  if (loading) {
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-soc-darker">
        <Loader2 className="w-8 h-8 text-soc-accent animate-spin" />
      </div>
    );
  }

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username || !password) {
      setError('Please enter both username and password.');
      return;
    }

    setError('');
    setIsSubmitting(true);

    try {
      await login(username, password);
    } catch (err) {
      setError(err.response?.data?.message || 'Invalid credentials or server error.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-soc-darker p-4">
      <div className="w-full max-w-md">
        <div className="bg-soc-card border border-soc-border rounded-xl shadow-2xl overflow-hidden">
          <div className="p-8 text-center border-b border-soc-border bg-soc-dark/50">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-soc-accent/10 text-soc-accent mb-4">
              <Shield className="w-8 h-8" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">STIS SOC</h1>
            <p className="text-gray-400 mt-2 text-sm">Security Operation Center Dashboard</p>
          </div>

          <div className="p-8">
            {error && (
              <div className="mb-6 p-4 bg-soc-danger/10 border border-soc-danger/30 rounded-lg flex items-start text-soc-danger text-sm">
                <AlertCircle className="w-5 h-5 mr-3 flex-shrink-0 mt-0.5" />
                <p>{error}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Username</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <User className="h-5 w-5 text-gray-500" />
                  </div>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="block w-full pl-10 pr-3 py-2.5 bg-soc-dark border border-soc-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-soc-accent focus:border-transparent transition-shadow"
                    placeholder="admin"
                    autoComplete="username"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Password</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Lock className="h-5 w-5 text-gray-500" />
                  </div>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="block w-full pl-10 pr-3 py-2.5 bg-soc-dark border border-soc-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-soc-accent focus:border-transparent transition-shadow"
                    placeholder="••••••••"
                    autoComplete="current-password"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full flex justify-center items-center py-2.5 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-soc-accent hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-soc-accent focus:ring-offset-soc-darker transition-colors disabled:opacity-70 disabled:cursor-not-allowed"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                    Authenticating...
                  </>
                ) : (
                  'Sign in to Dashboard'
                )}
              </button>
            </form>
          </div>
        </div>

        <p className="text-center text-sm text-gray-500 mt-8">
          &copy; {new Date().getFullYear()} STIS SOC. All rights reserved.
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
