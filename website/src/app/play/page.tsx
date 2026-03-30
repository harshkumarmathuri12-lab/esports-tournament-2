"use client";

import { Suspense, useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { brand } from "@config/brand";
import { LoadingSpinner } from "@/components/ui";

type User = { id: string; email: string; displayName: string; coins: number; isBlocked?: boolean };
type Game = { id: string; name: string; imageUrl: string | null };
type GameMode = { id: string; gameId: string; name: string; imageUrl: string | null };
type Match = {
  id: string;
  gameModeId: string;
  title: string;
  entryFee: number;
  roomCode: string | null;
  roomPassword: string | null;
  status: string;
  matchType?: string;
  maxParticipants?: number;
  startsAt?: string;
  prizePool?: { coinsPerKill?: number; totalPrizePool?: number };
};
type Transaction = { id: string; amount: number; type: string; note: string | null; status?: "pending" | "successful" | "failed" | "refunded"; createdAt: string };

const USER_KEY = "esports_play_user";

function formatTxDate(iso: string): string {
  const d = new Date(iso);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function getStoredUser(): User | null {
  if (typeof window === "undefined") return null;
  try {
    const s = localStorage.getItem(USER_KEY);
    return s ? JSON.parse(s) : null;
  } catch {
    return null;
  }
}

function setStoredUser(user: User | null) {
  if (typeof window === "undefined") return;
  if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
  else localStorage.removeItem(USER_KEY);
}

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const isGet = !options?.method || options.method === "GET";
  const bust = isGet && !path.includes("_cb=") ? `${path.includes("?") ? "&" : "?"}_cb=${Date.now()}` : "";
  const res = await fetch(`${path}${bust}`, {
    ...options,
    credentials: "include",
    cache: "no-store",
    headers: { "Content-Type": "application/json", ...options?.headers },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function PlayPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"games" | "coins" | "profile">("games");

  const refreshUser = useCallback(() => {
    api<User>("/api/users/me")
      .then((fresh) => {
        setUser(fresh);
        setStoredUser(fresh);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const stored = getStoredUser();
    setUser(stored);
    setLoading(false);
  }, []);

  useEffect(() => {
    const stored = getStoredUser();
    if (!stored) return;
    refreshUser();
  }, [refreshUser]);

  useEffect(() => {
    const t = searchParams.get("tab");
    if (t === "coins" || t === "games" || t === "profile") setTab(t);
    else if (t === "history") setTab("coins");
  }, [searchParams]);

  useEffect(() => {
    if (user?.isBlocked) setTab("profile");
  }, [user?.isBlocked]);

  const [globalToast, setGlobalToast] = useState<string | null>(null);
  const [supportUrl, setSupportUrl] = useState<string | null>(null);
  const fetchSupportUrl = useCallback(() => {
    api<{ url?: string | null }>("/api/customer-support")
      .then((r) => {
        const u = r.url;
        setSupportUrl(typeof u === "string" && u.trim() ? u.trim() : null);
      })
      .catch(() => setSupportUrl(null));
  }, []);
  useEffect(() => {
    fetchSupportUrl();
    const onVisible = () => {
      if (document.visibilityState === "visible") fetchSupportUrl();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [fetchSupportUrl]);
  useEffect(() => {
    if (user) fetchSupportUrl();
  }, [user, fetchSupportUrl]);
  useEffect(() => {
    const toastParam = searchParams.get("toast");
    if (toastParam === "deposit_success") {
      setGlobalToast("Deposit request submitted successfully");
      setTimeout(() => setGlobalToast(null), 3000);
      router.replace("/play?tab=history", { scroll: false });
    }
  }, [searchParams, router]);

  const onLoggedIn = useCallback((u: User) => {
    setStoredUser(u);
    setUser(u);
  }, []);

  const onLogout = useCallback(() => {
    fetch("/api/auth/logout", { method: "POST", credentials: "include" }).catch(() => {});
    setStoredUser(null);
    setUser(null);
  }, []);

  if (loading) {
    return <LoadingSpinner fullScreen label="Loading..." />;
  }

  if (!user) {
    return (
      <>
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-white/10 bg-[#0c0c0e]/95 px-4 py-3 backdrop-blur">
          <Link href="/" className="flex h-10 w-10 items-center justify-center rounded-full text-[#94A3B8] transition hover:bg-white/10 hover:text-white" aria-label="Back">
            <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <span className="font-ultimatum font-semibold text-white">{brand.appName}</span>
          <div className="w-20" />
        </header>
        <AuthScreen onLoggedIn={onLoggedIn} />
      </>
    );
  }

  return (
    <>
      {globalToast && (
        <div className="fixed bottom-6 left-1/2 z-50 -translate-x-1/2 rounded-xl bg-emerald-600 px-6 py-3 text-sm font-medium text-white shadow-lg">
          {globalToast}
        </div>
      )}
      <header className="sticky top-0 z-10 flex items-center justify-between border-b border-white/10 bg-[#0c0c0e]/95 px-4 py-3 backdrop-blur">
        <Link href="/" className="flex h-10 w-10 items-center justify-center rounded-full text-[#94A3B8] transition hover:bg-white/10 hover:text-white" aria-label="Back">
          <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </Link>
        <span className="font-ultimatum font-semibold text-white">{brand.appName}</span>
        {supportUrl ? (
          <a
            href={supportUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-sm text-[#94A3B8] hover:text-white"
          >
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 5.636l-3.536 3.536m0 5.656l3.536 3.536M9.172 9.172L5.636 5.636m3.536 9.192l-3.536 3.536M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-5 0a4 4 0 11-8 0 4 4 0 018 0z" />
            </svg>
            Support
          </a>
        ) : (
          <div className="w-20" />
        )}
      </header>
      <main className="mx-auto max-w-2xl pb-24">
        <div className="flex gap-2 border-b border-white/10 px-4 py-3">
          {user.isBlocked ? (
            <button className="rounded-full bg-[#f97316] px-4 py-2 text-sm font-medium text-white" disabled>
              Profile
            </button>
          ) : (
            (["games", "coins", "profile"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`rounded-full px-4 py-2 text-sm font-medium capitalize transition ${
                  tab === t
                    ? "bg-[#f97316] text-white"
                    : "text-[#94A3B8] hover:bg-white/5 hover:text-white"
                }`}
              >
                {t}
              </button>
            ))
          )}
        </div>
        {!user.isBlocked && tab === "games" && <GamesTab user={user} searchParams={searchParams} />}
        {!user.isBlocked && tab === "coins" && (
          <CoinsTab
            user={user}
            onRefreshUser={refreshUser}
            onShowToast={(msg) => { setGlobalToast(msg); setTimeout(() => setGlobalToast(null), 3000); }}
            initialSubTab={searchParams.get("tab") === "history" ? "history" : undefined}
          />
        )}
        {tab === "profile" && <ProfileTab user={user} onLogout={onLogout} />}
      </main>
    </>
  );
}

export default function PlayPage() {
  return (
    <Suspense fallback={
      <div className="flex min-h-screen items-center justify-center bg-[#0c0c0e]">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#f97316] border-t-transparent" />
      </div>
    }>
      <PlayPageContent />
    </Suspense>
  );
}

function AuthScreen({ onLoggedIn }: { onLoggedIn: (u: User) => void }) {
  const [isSignUp, setIsSignUp] = useState(true);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    const trimmed = email.trim();
    if (!trimmed) {
      setError("Email is required");
      return;
    }
    if (isSignUp) {
      if (!password || password.length < 6) {
        setError("Password must be at least 6 characters");
        return;
      }
      if (password !== confirmPassword) {
        setError("Passwords do not match");
        return;
      }
    } else {
      if (!password) {
        setError("Password is required");
        return;
      }
    }
    setLoading(true);
    setError(null);
    try {
      if (isSignUp) {
        const name = displayName.trim() || trimmed.split("@")[0] || "User";
        const { user } = await api<{ user: User }>("/api/auth/signup", {
          method: "POST",
          body: JSON.stringify({ email: trimmed, displayName: name, password }),
        });
        onLoggedIn(user);
      } else {
        const { user } = await api<{ user: User }>("/api/auth/signin", {
          method: "POST",
          body: JSON.stringify({ email: trimmed, password }),
        });
        onLoggedIn(user);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mx-auto max-w-sm px-6 py-12">
      <h1 className="text-2xl font-bold text-white">
        {isSignUp ? "Create Account" : "Sign In"}
      </h1>
      <p className="mt-2 text-sm text-[#94A3B8]">
        {isSignUp ? "Enter your email and set a password" : "Enter your email and password"}
      </p>
      <div className="mt-6 flex gap-3">
        <button
          onClick={() => {
            setIsSignUp(true);
            setError(null);
          }}
          className={`flex-1 rounded-full py-2 text-sm font-medium ${
            isSignUp ? "bg-[#f97316] text-white" : "bg-white/5 text-[#94A3B8]"
          }`}
        >
          Sign Up
        </button>
        <button
          onClick={() => {
            setIsSignUp(false);
            setError(null);
          }}
          className={`flex-1 rounded-full py-2 text-sm font-medium ${
            !isSignUp ? "bg-[#f97316] text-white" : "bg-white/5 text-[#94A3B8]"
          }`}
        >
          Sign In
        </button>
      </div>
      <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-6">
        <input
          type="email"
          value={email}
          onChange={(e) => {
            setEmail(e.target.value);
            setError(null);
          }}
          placeholder="Email"
          className="w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-white placeholder-[#64748B] outline-none focus:border-[#f97316]"
        />
        {isSignUp && (
          <input
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Display Name (optional)"
            className="mt-4 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-white placeholder-[#64748B] outline-none focus:border-[#f97316]"
          />
        )}
        <input
          type="password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            setError(null);
          }}
          placeholder={isSignUp ? "Password (min 6 characters)" : "Password"}
          className="mt-4 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-white placeholder-[#64748B] outline-none focus:border-[#f97316]"
        />
        {isSignUp && (
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => {
              setConfirmPassword(e.target.value);
              setError(null);
            }}
            placeholder="Confirm Password"
            className="mt-4 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-white placeholder-[#64748B] outline-none focus:border-[#f97316]"
          />
        )}
        {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
        <button
          onClick={handleSubmit}
          disabled={loading}
          className="mt-6 w-full rounded-xl bg-[#f97316] py-3 font-semibold text-white transition hover:opacity-90 disabled:opacity-50"
        >
          {loading ? "Please wait..." : isSignUp ? "Sign Up" : "Sign In"}
        </button>
      </div>
    </div>
  );
}

function GamesTab({ user, searchParams }: { user: User; searchParams: URLSearchParams }) {
  const [games, setGames] = useState<Game[]>([]);
  const [modes, setModes] = useState<GameMode[]>([]);
  const [matches, setMatches] = useState<Match[]>([]);
  const [selectedGame, setSelectedGame] = useState<Game | null>(null);
  const [selectedMode, setSelectedMode] = useState<GameMode | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingModes, setLoadingModes] = useState(false);
  const [loadingMatches, setLoadingMatches] = useState(false);

  useEffect(() => {
    api<Game[]>("/api/games")
      .then(setGames)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const modeIdFromUrl = searchParams.get("modeId");

  useEffect(() => {
    if (!modeIdFromUrl || games.length === 0) return;
    api<GameMode>(`/api/modes?modeId=${modeIdFromUrl}`)
      .then((mode) => {
        const game = games.find((g) => g.id === mode.gameId);
        if (game) {
          setSelectedGame(game);
          setSelectedMode(mode);
        }
      })
      .catch(() => {});
  }, [modeIdFromUrl, games]);

  useEffect(() => {
    if (!selectedGame) {
      setModes([]);
      setSelectedMode(null);
      setMatches([]);
      setLoadingModes(false);
      setLoadingMatches(false);
      return;
    }
    setLoadingModes(true);
    api<GameMode[]>(`/api/modes?gameId=${selectedGame.id}`)
      .then(setModes)
      .catch(() => setModes([]))
      .finally(() => setLoadingModes(false));
    if (!modeIdFromUrl) setSelectedMode(null);
    setMatches([]);
  }, [selectedGame]);

  useEffect(() => {
    if (!selectedMode) {
      setMatches([]);
      setLoadingMatches(false);
      return;
    }
    setLoadingMatches(true);
    api<Match[]>(`/api/matches?modeId=${selectedMode.id}`)
      .then(setMatches)
      .catch(() => setMatches([]))
      .finally(() => setLoadingMatches(false));
  }, [selectedMode]);

  if (loading) {
    return <LoadingSpinner size="md" compact label="Loading games..." />;
  }

  if (selectedMode) {
    if (loadingMatches) {
      return (
        <div className="p-4">
          <button onClick={() => setSelectedMode(null)} className="mb-4 text-sm text-[#f97316] hover:underline">
            ← Back to Modes
          </button>
          <h2 className="text-lg font-semibold text-white">Matches</h2>
          <LoadingSpinner size="md" compact label="Loading matches..." />
        </div>
      );
    }
    return (
      <MatchesView
        matches={matches}
        user={user}
        selectedMode={selectedMode}
        onBack={() => setSelectedMode(null)}
      />
    );
  }

  if (selectedGame) {
    if (loadingModes) {
      return (
        <div className="p-4">
          <button onClick={() => setSelectedGame(null)} className="mb-4 text-sm text-[#f97316] hover:underline">
            ← Back to Games
          </button>
          <h2 className="text-lg font-semibold text-white">Select Mode</h2>
          <LoadingSpinner size="md" compact label="Loading modes..." />
        </div>
      );
    }
    return (
      <div className="p-4">
        <button
          onClick={() => setSelectedGame(null)}
          className="mb-4 text-sm text-[#f97316] hover:underline"
        >
          ← Back to Games
        </button>
        <h2 className="text-lg font-semibold text-white">Select Mode</h2>
        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-3">
          {modes.map((m) => (
            <button
              key={m.id}
              onClick={() => setSelectedMode(m)}
              className="group relative w-full overflow-hidden rounded-xl text-left transition hover:opacity-95"
            >
              <div className="relative aspect-video w-full overflow-hidden rounded-xl bg-white/5">
                {m.imageUrl ? (
                  <img
                    src={m.imageUrl}
                    alt={m.name}
                    className="h-full w-full object-cover transition group-hover:scale-105"
                  />
                ) : (
                  <div className="flex h-full w-full items-center justify-center bg-gradient-to-br from-white/10 to-white/5">
                    <span className="text-2xl text-white/40">🎮</span>
                  </div>
                )}
                <div className="absolute inset-0 rounded-xl bg-gradient-to-t from-black/90 via-black/20 to-transparent" />
                <div className="absolute bottom-0 left-0 right-0 px-4 pb-3 pt-8">
                  <span className="line-clamp-2 text-sm font-semibold text-white drop-shadow-lg">{m.name}</span>
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-4">
      <h2 className="text-lg font-semibold text-white">Select Game</h2>
      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-3">
        {games.map((g) => (
          <button
            key={g.id}
            onClick={() => setSelectedGame(g)}
            className="group relative w-full overflow-hidden rounded-xl text-left transition hover:opacity-95"
          >
            <div className="relative aspect-video w-full overflow-hidden rounded-xl bg-white/5">
              {g.imageUrl ? (
                <img
                  src={g.imageUrl}
                  alt={g.name}
                  className="h-full w-full object-cover transition group-hover:scale-105"
                />
              ) : (
                <div className="flex h-full w-full items-center justify-center bg-gradient-to-br from-white/10 to-white/5">
                  <span className="text-2xl text-white/40">🎮</span>
                </div>
              )}
              <div className="absolute inset-0 rounded-xl bg-gradient-to-t from-black/90 via-black/20 to-transparent" />
              <div className="absolute bottom-0 left-0 right-0 px-4 pb-3 pt-8">
                <span className="line-clamp-2 text-sm font-semibold text-white drop-shadow-lg">{g.name}</span>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function formatMatchDateTime(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function MatchTypeTag({ type }: { type: string }) {
  const t = (type || "solo").toLowerCase();
  const styles =
    t === "solo"
      ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
      : t === "duo"
        ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
        : "bg-violet-500/20 text-violet-400 border-violet-500/40";
  return (
    <span className={`rounded-md border px-2 py-0.5 text-xs font-semibold uppercase ${styles}`}>
      {t}
    </span>
  );
}

function MatchesView({
  matches,
  user,
  selectedMode,
  onBack,
}: {
  matches: Match[];
  user: User;
  selectedMode: GameMode;
  onBack: () => void;
}) {
  const [statusTab, setStatusTab] = useState<"upcoming" | "ongoing" | "completed">("upcoming");
  const isCompleted = (s: string) => s === "completed" || s === "ended" || s === "cancelled";
  const filtered =
    statusTab === "upcoming"
      ? matches.filter((m) => m.status === "upcoming")
      : statusTab === "ongoing"
        ? matches.filter((m) => m.status === "ongoing")
        : matches.filter((m) => isCompleted(m.status));

  return (
    <div className="p-4">
      <button onClick={onBack} className="mb-4 text-sm text-[#f97316] hover:underline">
        ← Back to Modes
      </button>
      <h2 className="text-lg font-semibold text-white">Matches</h2>
      <div className="mt-4 flex gap-2 rounded-xl bg-white/5 p-1">
        {(["upcoming", "ongoing", "completed"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setStatusTab(tab)}
            className={`flex-1 rounded-lg py-2 text-sm font-medium capitalize transition ${
              statusTab === tab ? "bg-[#f97316] text-white" : "text-[#94A3B8] hover:bg-white/5 hover:text-white"
            }`}
          >
            {tab}
          </button>
        ))}
      </div>
      <div className="mt-4 space-y-3">
        {filtered.length === 0 ? (
          <div className="rounded-xl border border-white/10 bg-white/5 py-12 text-center text-[#94A3B8]">
            No {statusTab} matches
          </div>
        ) : (
          filtered.map((m) => (
            <MatchCard key={m.id} match={m} user={user} selectedMode={selectedMode} />
          ))
        )}
      </div>
    </div>
  );
}

function MatchCard({
  match,
  user,
  selectedMode,
}: {
  match: Match;
  user: User;
  selectedMode: GameMode;
}) {
  const router = useRouter();
  const cpk = match.prizePool?.coinsPerKill ?? 0;
  const prizePool = match.prizePool?.totalPrizePool ?? 0;
  const type = match.matchType || "solo";

  return (
    <button
      onClick={() =>
        router.push(`/play/matches/${match.id}?modeId=${selectedMode.id}&modeName=${encodeURIComponent(selectedMode.name)}`)
      }
      className="group flex w-full flex-col rounded-xl border border-white/10 bg-gradient-to-br from-white/5 to-white/[0.02] p-4 text-left transition hover:border-[#f97316]/40 hover:from-white/10 hover:to-white/5"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-white truncate">{match.title}</span>
            <MatchTypeTag type={type} />
          </div>
          <p className="mt-2 text-xs text-[#94A3B8]">{formatMatchDateTime(match.startsAt ?? "")}</p>
        </div>
        <svg
          className="h-5 w-5 shrink-0 text-[#94A3B8] transition group-hover:text-[#f97316]"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
      </div>
      <div className="mt-4 flex flex-wrap gap-3">
        <div className="flex items-center gap-1.5 rounded-lg bg-white/5 px-3 py-1.5">
          <span className="text-[10px] uppercase tracking-wider text-[#64748B]">Entry</span>
          <span className="font-semibold text-[#f97316]">{match.entryFee}</span>
          <span className="text-xs text-[#94A3B8]">coins</span>
        </div>
        <div className="flex items-center gap-1.5 rounded-lg bg-white/5 px-3 py-1.5">
          <span className="text-[10px] uppercase tracking-wider text-[#64748B]">Prize</span>
          <span className="font-semibold text-emerald-400">{prizePool}</span>
          <span className="text-xs text-[#94A3B8]">coins</span>
        </div>
        <div className="flex items-center gap-1.5 rounded-lg bg-white/5 px-3 py-1.5">
          <span className="text-[10px] uppercase tracking-wider text-[#64748B]">CPK</span>
          <span className="font-semibold text-amber-400">{cpk}</span>
          <span className="text-xs text-[#94A3B8]">/kill</span>
        </div>
      </div>
    </button>
  );
}

function CoinsTab({ user, onRefreshUser, onShowToast, initialSubTab }: { user: User; onRefreshUser?: () => void; onShowToast?: (msg: string) => void; initialSubTab?: "deposit" | "withdraw" | "history" }) {
  const router = useRouter();
  const [subTab, setSubTab] = useState<"deposit" | "withdraw" | "history">(initialSubTab ?? "deposit");

  useEffect(() => {
    if (initialSubTab) setSubTab(initialSubTab);
  }, [initialSubTab]);
  const [withdrawalCharge, setWithdrawalCharge] = useState(0);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [loadingInitial, setLoadingInitial] = useState(true);
  const [depositAmount, setDepositAmount] = useState("");
  const [amount, setAmount] = useState("");
  const [upiId, setUpiId] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoadingInitial(true);
    Promise.all([
      api<{ chargePercent?: number }>("/api/withdrawal-charge").then((r) => Number(r.chargePercent) || 0),
      api<Transaction[]>(`/api/users/${user.id}/transactions`).then((r) => r ?? []),
    ])
      .then(([charge, tx]) => {
        setWithdrawalCharge(Number.isFinite(charge) ? charge : 0);
        setTransactions(tx);
      })
      .catch(() => {})
      .finally(() => setLoadingInitial(false));
  }, [user.id]);

  useEffect(() => {
    if (subTab === "history" && onRefreshUser) onRefreshUser();
  }, [subTab, onRefreshUser]);

  useEffect(() => {
    if (subTab !== "withdraw") return;
    api<{ chargePercent?: number }>("/api/withdrawal-charge")
      .then((r) => setWithdrawalCharge(Number(r.chargePercent) || 0))
      .catch(() => {});
  }, [subTab]);

  const [refreshingTx, setRefreshingTx] = useState(false);
  const refreshTransactions = useCallback(() => {
    setRefreshingTx(true);
    api<Transaction[]>(`/api/users/${user.id}/transactions`)
      .then((r) => setTransactions(r ?? []))
      .catch(() => {})
      .finally(() => setRefreshingTx(false));
    onRefreshUser?.();
  }, [user.id, onRefreshUser]);

  const depositAmountNum = parseInt(depositAmount, 10);
  const canProceedToPayment = !isNaN(depositAmountNum) && depositAmountNum > 0;

  const withdrawAmountNum = parseInt(amount, 10);
  const withdrawAmountValid = !isNaN(withdrawAmountNum) && withdrawAmountNum > 0;
  const receiveAfterCharge =
    withdrawAmountValid && withdrawalCharge > 0
      ? Math.round(withdrawAmountNum * (1 - withdrawalCharge / 100))
      : withdrawAmountValid
        ? withdrawAmountNum
        : null;

  const handleProceedToPayment = () => {
    if (!canProceedToPayment) return;
    router.push(`/play/deposit?amount=${depositAmountNum}`);
  };

  const handleWithdraw = async () => {
    const amt = parseInt(amount, 10);
    if (!amt || amt <= 0 || !upiId.trim()) {
      setError("Enter valid amount and UPI ID");
      return;
    }
    if (user.coins < amt) {
      setError("Insufficient balance");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await api("/api/withdrawals", {
        method: "POST",
        body: JSON.stringify({ amount: amt, upiId: upiId.trim() }),
      });
      setAmount("");
      setUpiId("");
      onShowToast?.("Withdrawal request submitted successfully");
      onRefreshUser?.();
      api<Transaction[]>(`/api/users/${user.id}/transactions`).then((r) => setTransactions(r ?? [])).catch(() => {});
      setSubTab("history");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-4">
      <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
        <div className="flex justify-between">
          <span className="text-[#94A3B8]">Your Balance</span>
          <span className="font-bold text-[#f97316]">{user.coins} coins</span>
        </div>
      </div>
      <div className="mt-4 flex gap-2">
        {(["deposit", "withdraw", "history"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`rounded-full px-4 py-2 text-sm capitalize ${
              subTab === t ? "bg-[#f97316] text-white" : "bg-white/5 text-[#94A3B8]"
            }`}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="mt-6">
        {subTab === "deposit" && (
          <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
            <h3 className="font-medium text-white">Add Coins</h3>
            <p className="mt-2 text-sm text-[#94A3B8]">Enter the amount of coins you want to deposit</p>
            <input
              value={depositAmount}
              onChange={(e) => setDepositAmount(e.target.value)}
              placeholder="Amount (coins)"
              type="number"
              min={1}
              className="mt-4 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-white placeholder-[#64748B]"
            />
            {canProceedToPayment && (
              <button
                onClick={handleProceedToPayment}
                className="mt-4 w-full rounded-xl bg-[#f97316] py-3 font-semibold text-white"
              >
                Proceed to payment page
              </button>
            )}
          </div>
        )}
        {subTab === "withdraw" && (
          <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
            <h3 className="font-medium text-white">Withdraw Coins</h3>
            <p className="mt-4 text-sm text-[#94A3B8]">Fee: {withdrawalCharge}%</p>
            <input
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="Amount (coins)"
              type="number"
              min={1}
              className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-white placeholder-[#64748B]"
            />
            {receiveAfterCharge !== null && (
              <div className="mt-3 rounded-xl border border-[#f97316]/25 bg-[#f97316]/10 px-4 py-3">
                <p className="text-xs text-[#94A3B8]">You will receive (after fee)</p>
                <p className="mt-1 text-lg font-semibold text-[#f97316]">{receiveAfterCharge} coins</p>
                {withdrawalCharge > 0 && withdrawAmountValid && (
                  <p className="mt-2 text-xs text-[#64748B]">
                    {withdrawAmountNum} coins deducted from balance · {withdrawalCharge}% fee (
                    {Math.round((withdrawAmountNum * withdrawalCharge) / 100)} coins)
                  </p>
                )}
              </div>
            )}
            <input
              value={upiId}
              onChange={(e) => setUpiId(e.target.value)}
              placeholder="UPI ID"
              className="mt-3 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-white placeholder-[#64748B]"
            />
            {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
            <button
              onClick={handleWithdraw}
              disabled={loading}
              className="mt-4 w-full rounded-xl bg-[#f97316] py-3 font-semibold text-white disabled:opacity-50"
            >
              {loading ? "Submitting..." : "Submit"}
            </button>
          </div>
        )}
        {subTab === "history" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-lg font-semibold text-white">Transaction History</h3>
              <button
                type="button"
                onClick={refreshTransactions}
                disabled={refreshingTx}
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-white/5 text-[#94A3B8] hover:bg-white/10 hover:text-white disabled:opacity-50"
                title="Refresh"
              >
                <svg className={`h-5 w-5 ${refreshingTx ? "animate-spin" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </button>
            </div>
            {loadingInitial ? (
              <LoadingSpinner size="sm" compact label="Loading history..." />
            ) : (
            <div className="space-y-3">
              {transactions.map((tx) => (
                <div
                  key={tx.id}
                  className="group flex items-center gap-4 rounded-2xl border border-white/10 bg-white/[0.02] p-4 transition hover:border-white/15 hover:bg-white/5"
                >
                  <div
                    className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${
                      tx.amount >= 0 ? "bg-emerald-500/15" : "bg-red-500/15"
                    }`}
                  >
                    {tx.amount >= 0 ? (
                      <svg className="h-5 w-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
                      </svg>
                    ) : (
                      <svg className="h-5 w-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" />
                      </svg>
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-medium text-white">{tx.note || tx.type}</p>
                    <div className="mt-0.5 flex items-center gap-2">
                      {tx.status && (
                        <span
                          className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                            tx.status === "pending"
                              ? "bg-amber-500/20 text-amber-400 ring-1 ring-amber-500/30"
                              : tx.status === "successful"
                                ? "bg-emerald-500/20 text-emerald-400 ring-1 ring-emerald-500/30"
                                : tx.status === "failed"
                                  ? "bg-red-500/20 text-red-400 ring-1 ring-red-500/30"
                                  : tx.status === "refunded"
                                    ? "bg-purple-500/20 text-purple-400 ring-1 ring-purple-500/30"
                                    : ""
                          }`}
                        >
                          {tx.status === "pending" && "Pending"}
                          {tx.status === "successful" && "Successful"}
                          {tx.status === "failed" && "Rejected"}
                          {tx.status === "refunded" && "Refunded"}
                        </span>
                      )}
                      <span className="text-xs text-[#64748B]">{formatTxDate(tx.createdAt)}</span>
                    </div>
                  </div>
                  <div className="shrink-0 text-right">
                    <span
                      className={`text-lg font-semibold tabular-nums ${
                        tx.amount >= 0 ? "text-emerald-400" : "text-red-400"
                      }`}
                    >
                      {tx.amount >= 0 ? "+" : ""}{tx.amount}
                    </span>
                    <p className="text-xs text-[#94A3B8]">coins</p>
                  </div>
                </div>
              ))}
              {transactions.length === 0 && !loadingInitial && (
                <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-white/10 bg-white/[0.02] py-16 px-6">
                  <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-white/5">
                    <svg className="h-8 w-8 text-[#94A3B8]/60" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                  </div>
                  <p className="mt-4 text-center font-medium text-white">No transactions yet</p>
                  <p className="mt-1 text-center text-sm text-[#94A3B8]">Your deposit and withdrawal history will appear here</p>
                </div>
              )}
            </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ProfileTab({ user, onLogout }: { user: User; onLogout: () => void }) {
  return (
    <div className="p-4">
      <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
        <h3 className="font-medium text-white">Profile</h3>
        <div className="mt-4 space-y-3">
          <div className="flex justify-between">
            <span className="text-[#94A3B8]">User ID</span>
            <span className="font-medium text-white">{user.id}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[#94A3B8]">Email</span>
            <span className="text-white">{user.email}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[#94A3B8]">Display Name</span>
            <span className="text-white">{user.displayName}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[#94A3B8]">Coins</span>
            <span className="font-bold text-[#f97316]">{user.coins}</span>
          </div>
        </div>
        {user.isBlocked && (
          <div className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4">
            <p className="text-center font-medium text-amber-400">Your account is blocked. Contact customer support.</p>
          </div>
        )}
      </div>
      <button
        onClick={onLogout}
        className="mt-6 w-full rounded-xl bg-[#f97316] py-3 font-semibold text-white"
      >
        Logout
      </button>
    </div>
  );
}
