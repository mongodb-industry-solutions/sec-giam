'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { ShieldCheck, Eye, EyeOff, ArrowLeft, LogIn } from 'lucide-react';
import { API_BASE_URL } from '../../lib/constants';
import { ADMIN_TOKEN_KEY } from '../../lib/adminHelpers';

export function setAdminToken(token: string) {
  sessionStorage.setItem(ADMIN_TOKEN_KEY, token);
}

export default function AdminLoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        throw new Error((err as { error?: string }).error ?? 'Login failed');
      }

      const { token } = await res.json() as { token: string };
      setAdminToken(token);
      router.push('/admin/panel');
    } catch (err) {
      setError((err as Error).message ?? 'Login failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex items-center justify-center min-h-[80vh]">
      <div className="bg-gray-900 border border-orange-500/20 rounded-2xl shadow-xl w-full max-w-sm p-8">
        <div className="text-center mb-6">
          <div className="flex justify-center mb-3">
            <div className="w-14 h-14 rounded-full bg-orange-500/10 border border-orange-500/30 flex items-center justify-center">
              <ShieldCheck size={28} className="text-orange-400" />
            </div>
          </div>
          <h1 className="text-xl font-bold text-white">Administration Mode</h1>
          <p className="text-gray-400 text-sm mt-1">Enter admin credentials to continue</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => { setUsername(e.target.value); setError(null); }}
              placeholder="admin"
              autoComplete="username"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-orange-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Password</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => { setPassword(e.target.value); setError(null); }}
                placeholder="Enter admin password"
                autoComplete="current-password"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 pr-10 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-orange-500"
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200 transition-colors"
                tabIndex={-1}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          {error && (
            <div className="bg-red-900/30 border border-red-500/40 rounded-lg px-3 py-2 text-sm text-red-400">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={!username || !password || submitting}
            suppressHydrationWarning
            className="w-full bg-orange-600 text-white py-2.5 rounded-lg font-semibold hover:bg-orange-500 transition-colors disabled:opacity-40"
          >
            <span className="inline-flex items-center gap-2">
            <LogIn size={15} />
            {submitting ? 'Authenticating...' : 'Access Admin Panel'}
          </span>
          </button>
        </form>

        <div className="mt-5 text-center">
          <Link href="/" className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 transition-colors">
            <ArrowLeft size={12} /> Back to Mode Selection
          </Link>
        </div>

      </div>
    </div>
  );
}
