"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function AdminLoginPage() {
  const [adminname, setAdminname] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch("/api/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminname, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Login failed");
        return;
      }
      router.push("/admin");
      router.refresh();
    } catch {
      setError("Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="admin-page flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="admin-card rounded-2xl p-8">
          <h1 className="mb-2 text-xl font-bold text-white">Admin Login</h1>
          <p className="mb-6 text-sm text-slate-400">Sign in to access the admin dashboard</p>
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">Admin Name</label>
              <input
                type="text"
                value={adminname}
                onChange={(e) => setAdminname(e.target.value)}
                required
                autoComplete="username"
                className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
                placeholder="adminname"
              />
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
                className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
                placeholder="••••••••"
              />
            </div>
            {error && (
              <p className="rounded-lg bg-rose-500/20 px-4 py-2 text-sm text-rose-300">{error}</p>
            )}
            <button
              type="submit"
              disabled={loading}
              className="admin-btn-primary w-full rounded-xl px-6 py-3 font-medium text-white disabled:opacity-50"
            >
              {loading ? "Signing in..." : "Sign In"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
