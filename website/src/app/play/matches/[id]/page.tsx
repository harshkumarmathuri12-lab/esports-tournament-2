"use client";

import { Suspense, useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { brand } from "@config/brand";
import { LoadingSpinner } from "@/components/ui";

type User = { id: string; email: string; displayName: string; coins: number; isBlocked?: boolean };
type MatchDetail = {
  id: string;
  title: string;
  entryFee: number;
  status: string;
  matchType?: string;
  maxParticipants?: number;
  startsAt?: string;
  roomCode?: string | null;
  roomPassword?: string | null;
  prizePool?: { coinsPerKill?: number; totalPrizePool?: number; rankRewards?: { fromRank: number; toRank: number; coins: number }[] };
};
type Participant = {
  id: string;
  userId?: string;
  teamMembers: { inGameName: string; inGameUid: string; kills?: number }[];
  joinedAt: string;
  rank?: number;
};

const USER_KEY = "esports_play_user";
const JOINED_KEY_PREFIX = "esports_joined_";

function getStoredUser(): User | null {
  if (typeof window === "undefined") return null;
  try {
    const s = localStorage.getItem(USER_KEY);
    return s ? JSON.parse(s) : null;
  } catch {
    return null;
  }
}

function getStoredJoined(matchId: string, userId: string): boolean {
  if (typeof window === "undefined") return false;
  try {
    return localStorage.getItem(`${JOINED_KEY_PREFIX}${matchId}_${userId}`) === "1";
  } catch {
    return false;
  }
}

function setStoredJoined(matchId: string, userId: string, joined: boolean) {
  if (typeof window === "undefined") return;
  try {
    const key = `${JOINED_KEY_PREFIX}${matchId}_${userId}`;
    if (joined) localStorage.setItem(key, "1");
    else localStorage.removeItem(key);
  } catch {}
}

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const isGet = !options?.method || options.method === "GET";
  const bust =
    isGet && !path.includes("_cb=") && !path.includes("?t=")
      ? `${path.includes("?") ? "&" : "?"}_cb=${Date.now()}`
      : "";
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

function formatMatchDateTime(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    weekday: "long",
    month: "long",
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

function computeCoinsWon(
  p: Participant,
  cpk: number,
  rankRewards: { fromRank: number; toRank: number; coins: number }[]
): number {
  const totalKills = (p.teamMembers ?? []).reduce((s, t) => s + (t.kills ?? 0), 0);
  let coins = totalKills * cpk;
  if (typeof p.rank === "number" && p.rank >= 1 && rankRewards?.length) {
    for (const r of rankRewards) {
      if (p.rank >= r.fromRank && p.rank <= r.toRank) {
        coins += r.coins;
        break;
      }
    }
  }
  return coins;
}

function MatchDetailContent() {
  const params = useParams();
  const searchParams = useSearchParams();
  const id = params.id as string;
  const modeId = searchParams.get("modeId");
  const modeName = searchParams.get("modeName") || "Matches";

  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMatch, setLoadingMatch] = useState(true);
  const [match, setMatch] = useState<MatchDetail | null>(null);
  const [participants, setParticipants] = useState<Participant[]>([]);
  const [inGameName, setInGameName] = useState("");
  const [inGameUid, setInGameUid] = useState("");
  const [joinLoading, setJoinLoading] = useState(false);
  const [joinError, setJoinError] = useState<string | null>(null);
  const [hasJoinedOverride, setHasJoinedOverride] = useState(false);

  const refreshUser = useCallback(() => {
    api<User>("/api/users/me")
      .then((u) => setUser(u))
      .catch(() => setUser(null));
  }, []);

  useEffect(() => {
    const stored = getStoredUser();
    setUser(stored);
    setLoading(false);
  }, []);

  useEffect(() => {
    const stored = getStoredUser();
    if (stored) refreshUser();
  }, [refreshUser]);

  const fetchMatch = useCallback(() => {
    if (!id) return;
    api<MatchDetail>(`/api/matches/${id}`)
      .then(setMatch)
      .catch(() => setMatch(null));
  }, [id]);

  const fetchParticipants = useCallback(() => {
    if (!id) return;
    api<Participant[]>(`/api/matches/${id}/participants`)
      .then(setParticipants)
      .catch(() => setParticipants([]));
  }, [id]);

  const refreshMatchAndParticipants = useCallback(() => {
    if (!id) return;
    setLoadingMatch(true);
    Promise.all([api<MatchDetail>(`/api/matches/${id}`), api<Participant[]>(`/api/matches/${id}/participants`)])
      .then(([m, parts]) => {
        setMatch(m);
        setParticipants(parts ?? []);
      })
      .catch(() => {})
      .finally(() => setLoadingMatch(false));
  }, [id]);

  useEffect(() => {
    if (!id) {
      setLoadingMatch(false);
      return;
    }
    refreshMatchAndParticipants();
  }, [id, refreshMatchAndParticipants]);

  useEffect(() => {
    if (!id || !user) return;
    const t = setInterval(() => {
      fetchMatch();
      fetchParticipants();
    }, 8000);
    return () => clearInterval(t);
  }, [id, user, fetchMatch, fetchParticipants]);

  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === "visible" && id) {
        fetchMatch();
        fetchParticipants();
      }
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [id, fetchMatch, fetchParticipants]);

  useEffect(() => {
    if (user?.id && id) {
      setHasJoinedOverride(getStoredJoined(id, user.id));
    } else {
      setHasJoinedOverride(false);
    }
  }, [user?.id, id]);

  const hasJoined =
    (user && participants.some((p) => String(p.userId) === String(user.id))) || hasJoinedOverride;

  const handleJoin = async () => {
    if (!inGameName.trim() || !inGameUid.trim()) {
      setJoinError("Enter in-game name and UID");
      return;
    }
    setJoinLoading(true);
    setJoinError(null);
    try {
      await api(`/api/matches/${id}/join`, {
        method: "POST",
        body: JSON.stringify({
          inGameName: inGameName.trim(),
          inGameUid: inGameUid.trim(),
        }),
      });
      setInGameName("");
      setInGameUid("");
      setHasJoinedOverride(true);
      if (user?.id && id) setStoredJoined(id, user.id, true);
      refreshUser();
      await Promise.all([
        api<MatchDetail>(`/api/matches/${id}`).then(setMatch),
        api<Participant[]>(`/api/matches/${id}/participants`).then(setParticipants),
      ]);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to join";
      if (msg.toLowerCase().includes("already registered")) {
        setInGameName("");
        setInGameUid("");
        setHasJoinedOverride(true);
        if (user?.id && id) setStoredJoined(id, user.id, true);
        await Promise.all([
          api<MatchDetail>(`/api/matches/${id}`).then(setMatch),
          api<Participant[]>(`/api/matches/${id}/participants`).then(setParticipants),
        ]);
      } else {
        setJoinError(msg);
      }
    } finally {
      setJoinLoading(false);
    }
  };

  const canJoin =
    match?.status === "upcoming" &&
    user &&
    user.coins >= (match?.entryFee ?? 0) &&
    !user.isBlocked &&
    !hasJoined &&
    !hasJoinedOverride;
  const backHref = modeId ? `/play?tab=games&modeId=${modeId}` : "/play";

  if (loading) {
    return <LoadingSpinner fullScreen label="Loading..." />;
  }

  if (!user) {
    return (
      <>
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-white/10 bg-[#0c0c0e]/95 px-4 py-3 backdrop-blur">
          <Link
            href={backHref}
            className="flex h-10 w-10 items-center justify-center rounded-full text-[#94A3B8] transition hover:bg-white/10 hover:text-white"
            aria-label="Back"
          >
            <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <span className="font-ultimatum font-semibold text-white">{brand.appName}</span>
          <div className="w-10" />
        </header>
        <div className="flex min-h-[60vh] flex-col items-center justify-center p-6 text-center">
          <p className="text-[#94A3B8]">Sign in to view match details</p>
          <Link
            href="/play"
            className="mt-4 rounded-xl bg-[#f97316] px-6 py-2 font-semibold text-white"
          >
            Sign In
          </Link>
        </div>
      </>
    );
  }

  if (loadingMatch) {
    return (
      <>
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-white/10 bg-[#0c0c0e]/95 px-4 py-3 backdrop-blur">
          <Link
            href={backHref}
            className="flex h-10 w-10 items-center justify-center rounded-full text-[#94A3B8] transition hover:bg-white/10 hover:text-white"
          >
            <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <span className="font-ultimatum font-semibold text-white">{brand.appName}</span>
          <div className="w-10" />
        </header>
        <LoadingSpinner fullScreen label="Loading match..." />
      </>
    );
  }

  if (!match) {
    return (
      <>
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-white/10 bg-[#0c0c0e]/95 px-4 py-3 backdrop-blur">
          <Link
            href={backHref}
            className="flex h-10 w-10 items-center justify-center rounded-full text-[#94A3B8] transition hover:bg-white/10 hover:text-white"
          >
            <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <span className="font-ultimatum font-semibold text-white">{brand.appName}</span>
          <div className="w-10" />
        </header>
        <div className="flex min-h-[60vh] items-center justify-center p-6">
          <p className="text-[#94A3B8]">Match not found</p>
        </div>
      </>
    );
  }

  const cpk = match.prizePool?.coinsPerKill ?? 0;
  const prizePool = match.prizePool?.totalPrizePool ?? 0;
  const rankRewards = match.prizePool?.rankRewards ?? [];
  const type = match.matchType || "solo";
  const isCompleted = match.status === "completed" || match.status === "ended";

  return (
    <>
      <header className="sticky top-0 z-10 flex items-center justify-between border-b border-white/10 bg-[#0c0c0e]/95 px-4 py-3 backdrop-blur">
        <Link
          href={backHref}
          className="flex h-10 w-10 items-center justify-center rounded-full text-[#94A3B8] transition hover:bg-white/10 hover:text-white"
          aria-label="Back"
        >
          <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </Link>
        <span className="font-ultimatum font-semibold text-white">{brand.appName}</span>
        <div className="w-10" />
      </header>

      <main className="mx-auto max-w-2xl px-4 pb-24 pt-6">
        <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-white/5 to-white/[0.02] p-6">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white">{match.title}</h1>
            <MatchTypeTag type={type} />
          </div>
          <p className="mt-2 text-sm text-[#94A3B8]">{formatMatchDateTime(match.startsAt ?? "")}</p>

          <div className="mt-6 grid grid-cols-3 gap-3">
            <div className="rounded-xl bg-white/5 p-4 text-center">
              <p className="text-[10px] uppercase tracking-wider text-[#64748B]">Entry Fee</p>
              <p className="mt-1 font-bold text-[#f97316]">{match.entryFee}</p>
              <p className="text-xs text-[#94A3B8]">coins</p>
            </div>
            <div className="rounded-xl bg-white/5 p-4 text-center">
              <p className="text-[10px] uppercase tracking-wider text-[#64748B]">Prize Pool</p>
              <p className="mt-1 font-bold text-emerald-400">{prizePool}</p>
              <p className="text-xs text-[#94A3B8]">coins</p>
            </div>
            <div className="rounded-xl bg-white/5 p-4 text-center">
              <p className="text-[10px] uppercase tracking-wider text-[#64748B]">Coins/Kill</p>
              <p className="mt-1 font-bold text-amber-400">{cpk}</p>
              <p className="text-xs text-[#94A3B8]">per kill</p>
            </div>
          </div>

          {hasJoined &&
            match.roomCode &&
            match.roomPassword &&
            (match.status === "upcoming" || match.status === "ongoing") && (
              <div className="mt-6 rounded-xl border border-[#f97316]/30 bg-[#f97316]/10 p-4">
                <p className="text-sm font-semibold text-[#f97316]">Room Details</p>
                <p className="mt-1 font-mono text-white">Code: {match.roomCode}</p>
                <p className="font-mono text-white">Password: {match.roomPassword}</p>
              </div>
            )}

          {match.prizePool?.rankRewards && match.prizePool.rankRewards.length > 0 && (
            <div className="mt-6">
              <p className="text-sm font-semibold text-white">Rank Rewards</p>
              <div className="mt-2 space-y-1">
                {match.prizePool.rankRewards.map((r, i) => (
                  <div key={i} className="flex justify-between text-sm text-[#94A3B8]">
                    <span>Rank {r.fromRank}–{r.toRank}</span>
                    <span className="text-emerald-400">{r.coins} coins</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {hasJoined && match.status === "upcoming" && (
          <div className="mt-6 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-6">
            <p className="flex items-center gap-2 font-semibold text-emerald-400">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              You have already registered for this match
            </p>
          </div>
        )}

        {canJoin && (
          <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-6">
            <h2 className="text-lg font-semibold text-white">Join Match</h2>
            <p className="mt-1 text-sm text-[#94A3B8]">Enter your in-game details</p>
            <input
              value={inGameName}
              onChange={(e) => setInGameName(e.target.value)}
              placeholder="In-game Name"
              className="mt-4 w-full rounded-xl border border-white/10 bg-[#0c0c0e] px-4 py-3 text-white placeholder-[#64748B] outline-none focus:border-[#f97316]"
            />
            <input
              value={inGameUid}
              onChange={(e) => setInGameUid(e.target.value)}
              placeholder="In-game UID"
              className="mt-3 w-full rounded-xl border border-white/10 bg-[#0c0c0e] px-4 py-3 text-white placeholder-[#64748B] outline-none focus:border-[#f97316]"
            />
            {joinError && <p className="mt-2 text-sm text-red-400">{joinError}</p>}
            <button
              onClick={handleJoin}
              disabled={joinLoading}
              className="mt-4 w-full rounded-xl bg-[#f97316] py-3 font-semibold text-white transition hover:opacity-90 disabled:opacity-50"
            >
              {joinLoading ? "Joining..." : `Join for ${match.entryFee} coins`}
            </button>
          </div>
        )}

        {match.status === "upcoming" && !hasJoined && !canJoin && user.coins < (match.entryFee ?? 0) && (
          <div className="mt-6 rounded-2xl border border-amber-500/30 bg-amber-500/10 p-6">
            <p className="font-medium text-amber-400">
              You need {match.entryFee} coins to join. You have {user.coins} coins.
            </p>
            <p className="mt-1 text-sm text-[#94A3B8]">Add coins from the Coins tab to join this match.</p>
          </div>
        )}

        {match.status !== "upcoming" && !hasJoined && user.coins < (match.entryFee ?? 0) && (
          <p className="mt-6 text-center text-sm text-[#94A3B8]">
            Registration closed. You need {match.entryFee} coins to join upcoming matches.
          </p>
        )}

        <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-6">
          <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">
                {isCompleted ? "Final Standings" : "Participants"} ({participants.length}/{match.maxParticipants ?? 100})
              </h2>
              {isCompleted && (
                <p className="mt-0.5 text-xs text-[#94A3B8]">Rank, kills, and coins won per player</p>
              )}
            </div>
            <button
              type="button"
              onClick={() => {
                fetchMatch();
                fetchParticipants();
              }}
              className="rounded-lg px-3 py-1.5 text-sm text-[#94A3B8] hover:bg-white/5 hover:text-white"
            >
              Refresh
            </button>
          </div>
          {participants.length === 0 ? (
            <p className="mt-4 text-sm text-[#94A3B8]">No participants yet</p>
          ) : (
            <div className="mt-4 space-y-2">
              {participants.map((p, idx) => {
                const totalKills = (p.teamMembers ?? []).reduce((s, t) => s + (t.kills ?? 0), 0);
                const coinsWon = isCompleted ? computeCoinsWon(p, cpk, rankRewards) : 0;
                return (
                  <div
                    key={p.id}
                    className="flex flex-col gap-2 rounded-xl bg-[#0c0c0e]/50 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      {match.status !== "upcoming" && (
                        <span className="shrink-0 text-sm font-medium text-[#64748B]">
                          #{typeof p.rank === "number" ? p.rank : idx + 1}
                        </span>
                      )}
                      <div className="min-w-0">
                        <p className="truncate font-medium text-white">{p.teamMembers[0]?.inGameName ?? "—"}</p>
                        <p className="truncate text-xs text-[#94A3B8]">UID: {p.teamMembers[0]?.inGameUid ?? "—"}</p>
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 sm:shrink-0 sm:justify-end">
                      {match.status !== "upcoming" && totalKills > 0 && (
                        <span className="rounded-full bg-amber-500/20 px-2.5 py-1 text-xs font-semibold text-amber-400">
                          {totalKills} kill{totalKills !== 1 ? "s" : ""}
                        </span>
                      )}
                      {isCompleted && coinsWon > 0 && (
                        <span className="rounded-full bg-emerald-500/20 px-2.5 py-1 text-xs font-semibold text-emerald-400">
                          +{coinsWon} coins
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </main>
    </>
  );
}

export default function MatchDetailPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-[#0c0c0e]">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#f97316] border-t-transparent" />
        </div>
      }
    >
      <MatchDetailContent />
    </Suspense>
  );
}
