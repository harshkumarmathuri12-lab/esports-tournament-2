"use client";

import { Suspense, useState, useEffect } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";

const USER_KEY = "esports_play_user";

type User = { id: string; email: string; displayName: string; coins: number; isBlocked?: boolean };

function getStoredUser(): User | null {
  if (typeof window === "undefined") return null;
  try {
    const s = localStorage.getItem(USER_KEY);
    return s ? JSON.parse(s) : null;
  } catch {
    return null;
  }
}

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...options,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...options?.headers },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function DepositPaymentPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const amountParam = searchParams.get("amount") ?? "";
  const amountNum = parseInt(amountParam, 10);
  const isValidAmount = !isNaN(amountNum) && amountNum > 0;

  const [user, setUser] = useState<User | null>(null);
  const [mounted, setMounted] = useState(false);
  const [depositQr, setDepositQr] = useState<string | null>(null);
  const [utr, setUtr] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setUser(getStoredUser());
    setMounted(true);
  }, []);

  useEffect(() => {
    api<User>("/api/users/me")
      .then((u) => {
        setUser(u);
        if (typeof window !== "undefined" && u) {
          try { localStorage.setItem(USER_KEY, JSON.stringify(u)); } catch {}
        }
        if (u?.isBlocked) router.replace("/play");
      })
      .catch(() => {});
  }, [router]);

  useEffect(() => {
    api<{ url?: string }>("/api/deposit-qr")
      .then((r) => r.url ?? null)
      .then(setDepositQr)
      .catch(() => setDepositQr(null));
  }, []);

  const handleSubmit = async () => {
    if (!user || !isValidAmount || !utr.trim()) {
      setError("Enter UTR / Transaction ID");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await api("/api/deposits", {
        method: "POST",
        body: JSON.stringify({ amount: amountNum, utr: utr.trim() }),
      });
      setUtr("");
      setError(null);
      router.push("/play?tab=history&toast=deposit_success");
      return;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    } finally {
      setLoading(false);
    }
  };

  if (!mounted) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#f97316] border-t-transparent" />
      </div>
    );
  }

  if (!user || !isValidAmount) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center p-6">
        <p className="text-center text-[#94A3B8]">Invalid or missing amount. Please start from the Coins tab.</p>
        <Link href="/play" className="mt-4 text-[#f97316] hover:underline">
          ← Back to Play
        </Link>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center p-6">
      <Link
        href="/play?tab=coins"
        className="absolute left-4 top-4 text-sm text-[#f97316] hover:underline"
      >
        ← Back
      </Link>
      <div className="w-full max-w-sm rounded-2xl border border-white/10 bg-white/5 p-6">
        <h2 className="text-center text-lg font-semibold text-white">Complete Payment</h2>
        <div className="mt-6 flex flex-col items-center">
          {depositQr ? (
            <img
              src={depositQr}
              alt="Payment QR"
              className="h-52 w-52 rounded-xl object-cover"
            />
          ) : (
            <div className="flex h-52 w-52 items-center justify-center rounded-xl bg-white/10">
              <span className="text-4xl text-white/40">QR</span>
            </div>
          )}
          <p className="mt-5 text-xl font-semibold text-white">Pay ₹{amountNum}</p>
          <p className="mt-1 text-sm text-[#94A3B8]">After payment, enter your UTR below</p>
        </div>
        <input
          value={utr}
          onChange={(e) => setUtr(e.target.value)}
          placeholder="UTR / Transaction ID"
          className="mt-6 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-white placeholder-[#64748B]"
        />
        {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
        <button
          onClick={handleSubmit}
          disabled={loading}
          className="mt-4 w-full rounded-xl bg-[#f97316] py-3 font-semibold text-white disabled:opacity-50"
        >
          {loading ? "Submitting..." : "Submit"}
        </button>
      </div>
    </div>
  );
}

export default function DepositPaymentPage() {
  return (
    <Suspense fallback={
      <div className="flex min-h-screen items-center justify-center bg-[#0c0c0e]">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#f97316] border-t-transparent" />
      </div>
    }>
      <DepositPaymentPageContent />
    </Suspense>
  );
}
