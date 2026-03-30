"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { LoadingSpinner } from "@/components/ui";

type Tab = "games" | "coins" | "admins" | "users";
type Game = { id: string; name: string; imageUrl: string | null };
type GameMode = { id: string; gameId: string; name: string; imageUrl: string | null };
type MatchType = "solo" | "duo" | "squad";
type RankReward = { fromRank: number; toRank: number; coins: number };
type PrizePool = { coinsPerKill: number; totalPrizePool?: number; rankRewards: RankReward[] };
type Match = {
  id: string;
  gameModeId: string;
  title: string;
  entryFee: number;
  roomCode: string | null;
  roomPassword: string | null;
  status: string;
  registrationLocked?: boolean;
  matchType?: MatchType;
  prizePool?: PrizePool;
  scheduledAt?: string;
  maxParticipants?: number;
};
type User = { id: string; email: string; displayName: string; coins: number; isBlocked?: boolean };

type AdminSession = {
  id: string;
  adminname: string;
  isMasterAdmin: boolean;
  usersAccess: boolean;
  coinsAccess: boolean;
  gamesAccessType: "all" | "specific";
  allowedGameIds: string[];
};

export default function AdminPage() {
  const router = useRouter();
  const [session, setSession] = useState<AdminSession | null>(null);
  const [tab, setTab] = useState<Tab>("games");
  const [selectedGameId, setSelectedGameId] = useState<string | null>(null);
  const [selectedModeId, setSelectedModeId] = useState<string | null>(null);
  const [games, setGames] = useState<Game[]>([]);
  const [modes, setModes] = useState<GameMode[]>([]);
  const [matches, setMatches] = useState<Match[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const hasSpecificGameAccess = session?.gamesAccessType === "specific" && !session?.isMasterAdmin;
  const hasSingleGameAccess = hasSpecificGameAccess && session && session.allowedGameIds.length === 1;

  const visibleTabs: { id: Tab; label: string }[] = [];
  if (session) {
    if (session.isMasterAdmin || session.gamesAccessType === "all" || session.allowedGameIds.length > 0) {
      visibleTabs.push({ id: "games", label: "Games" });
    }
    if (session.coinsAccess) visibleTabs.push({ id: "coins", label: "Coins" });
    if (session.isMasterAdmin) visibleTabs.push({ id: "admins", label: "Admins" });
    if (session.usersAccess || session.coinsAccess) visibleTabs.push({ id: "users", label: "Users" });
  }
  useEffect(() => {
    if (!session) return;
    const hasGames = session.isMasterAdmin || session.gamesAccessType === "all" || session.allowedGameIds.length > 0;
    const validTabs: Tab[] = [];
    if (hasGames) validTabs.push("games");
    if (session.coinsAccess) validTabs.push("coins");
    if (session.isMasterAdmin) validTabs.push("admins");
    if (session.usersAccess || session.coinsAccess) validTabs.push("users");
    setTab((prev) => (validTabs.length > 0 && !validTabs.includes(prev) ? validTabs[0] : prev));
  }, [session]);

  // When admin has access to only one specific game, open directly to that game's modes
  useEffect(() => {
    if (hasSingleGameAccess && games.length > 0 && !selectedGameId && !selectedModeId) {
      const allowedId = session!.allowedGameIds[0];
      if (games.some((g) => g.id === allowedId)) {
        setSelectedGameId(allowedId);
      }
    }
  }, [hasSingleGameAccess, games, session, selectedGameId, selectedModeId]);

  const fetchData = async (showLoading = true) => {
    const sessionRes = await fetch("/api/admin/session");
    const sessionData = await sessionRes.json();
    if (!sessionData.admin) return;
    setSession(sessionData.admin);

    if (showLoading) setLoading(true);
    try {
      const [gRes, mRes, matRes, uRes] = await Promise.all([
        fetch("/api/admin/games"),
        fetch("/api/admin/modes"),
        fetch("/api/admin/matches"),
        (sessionData.admin.usersAccess || sessionData.admin.coinsAccess) ? fetch("/api/admin/users") : Promise.resolve(null),
      ]);
      if (gRes.ok) setGames(await gRes.json());
      if (mRes.ok) setModes(await mRes.json());
      if (matRes.ok) setMatches(await matRes.json());
      if (uRes?.ok) setUsers(await uRes.json());
    } catch (e) {
      setMessage({ type: "err", text: "Failed to load data" });
    } finally {
      if (showLoading) setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const showMsg = (type: "ok" | "err", text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 3000);
  };

  const handleLogout = async () => {
    await fetch("/api/admin/logout", { method: "POST" });
    router.replace("/admin/login");
    router.refresh();
  };

  return (
    <>
      <header className="admin-header fixed top-0 left-0 right-0 z-50">
        <nav className="mx-auto flex max-w-4xl justify-center gap-1 px-4 py-4 sm:gap-2 sm:px-6">
          {visibleTabs.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => {
                setTab(t.id);
                if (t.id !== "games") {
                  setSelectedGameId(null);
                  setSelectedModeId(null);
                } else if (hasSingleGameAccess && session && games.length > 0) {
                  setSelectedGameId(session.allowedGameIds[0]);
                  setSelectedModeId(null);
                }
              }}
              className={`admin-tab rounded-full px-5 py-2.5 text-sm font-medium sm:px-6 ${
                tab === t.id
                  ? "bg-gradient-to-r from-orange-500 to-amber-600 text-white shadow-lg shadow-orange-500/25"
                  : "text-slate-400 hover:bg-white/5 hover:text-white"
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>
      <div className="pb-20 pt-24">
        {session && (
          <div className="mx-auto flex max-w-4xl items-center justify-between gap-4 px-4 pb-4 sm:px-6">
            <span className="text-sm font-bold text-slate-200">
              Hi, {session.adminname}
            </span>
            <button
              type="button"
              onClick={handleLogout}
              className="flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-red-500"
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
              Logout
            </button>
          </div>
        )}
        <div className="mx-auto max-w-3xl px-4 sm:px-6">
        {message && (
          <div
            className={`mb-6 flex items-center gap-3 rounded-xl px-4 py-3.5 shadow-lg ${
              message.type === "ok"
                ? "bg-emerald-500/20 text-emerald-200 border border-emerald-500/30"
                : "bg-rose-500/20 text-rose-200 border border-rose-500/30"
            }`}
          >
            <span className={`h-2 w-2 rounded-full ${message.type === "ok" ? "bg-emerald-400" : "bg-rose-400"}`} />
            {message.text}
          </div>
        )}

        {loading ? (
          <div className="admin-card flex flex-col items-center justify-center rounded-2xl p-16">
            <LoadingSpinner size="lg" label="Loading dashboard..." />
          </div>
        ) : (
          <>
            {tab === "games" && (
              selectedModeId ? (
                <MatchesSection
                  games={games}
                  modes={modes}
                  matches={matches.filter((m) => m.gameModeId === selectedModeId)}
                  modeId={selectedModeId}
                  users={users}
                  onBack={() => setSelectedModeId(null)}
                  onSuccess={(opts?: { silent?: boolean }) => { fetchData(!opts?.silent); showMsg("ok", "Updated"); }}
                />
              ) : selectedGameId ? (
                <ModesSection
                  games={games}
                  modes={modes.filter((m) => m.gameId === selectedGameId)}
                  gameId={selectedGameId}
                  onBack={hasSingleGameAccess ? undefined : () => setSelectedGameId(null)}
                  onSelectMode={(id) => setSelectedModeId(id)}
                  onSuccess={() => { fetchData(); showMsg("ok", "Mode created"); }}
                />
              ) : (
                <GamesSection
                  games={games}
                  onSelectGame={(id) => setSelectedGameId(id)}
                  onSuccess={() => { fetchData(); showMsg("ok", "Game created"); }}
                  showCreateGame={!hasSpecificGameAccess}
                />
              )
            )}
            {tab === "coins" && (
              <CoinsSection
                users={users}
                onSuccess={() => { fetchData(false); showMsg("ok", "Updated"); }}
              />
            )}
            {tab === "admins" && session?.isMasterAdmin && (
              <CreateAdminSection
                games={games}
                onSuccess={() => { fetchData(); showMsg("ok", "Admin created"); }}
              />
            )}
            {tab === "users" && (
              <UsersSection
                users={users}
                canAddCoins={!!session?.coinsAccess}
                onSuccess={() => fetchData()}
              />
            )}
          </>
        )}
        </div>
      </div>
    </>
  );
}

function ItemMenu({
  onDelete,
  onRename,
  currentName,
  stopPropagation = true,
}: {
  onDelete: () => void;
  onRename: (newName: string) => void;
  currentName: string;
  stopPropagation?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, [open]);

  const handleRename = () => {
    setOpen(false);
    const newName = prompt("Enter new name", currentName);
    if (newName && newName.trim()) onRename(newName.trim());
  };

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={(e) => {
          if (stopPropagation) e.stopPropagation();
          setOpen((o) => !o);
        }}
        className="rounded p-1.5 text-slate-400 transition hover:bg-white/10 hover:text-white"
        aria-label="Options"
      >
        <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
          <circle cx="12" cy="6" r="1.5" />
          <circle cx="12" cy="12" r="1.5" />
          <circle cx="12" cy="18" r="1.5" />
        </svg>
      </button>
      {open && (
        <div className="absolute right-0 top-full z-20 mt-1 min-w-[120px] rounded-lg border border-slate-600 bg-slate-800 py-1 shadow-xl">
          <button
            type="button"
            onClick={(e) => {
              if (stopPropagation) e.stopPropagation();
              handleRename();
            }}
            className="flex w-full items-center gap-2 px-4 py-2 text-left text-sm text-slate-200 hover:bg-slate-700"
          >
            Rename
          </button>
          <button
            type="button"
            onClick={(e) => {
              if (stopPropagation) e.stopPropagation();
              setOpen(false);
              if (confirm("Delete this item?")) onDelete();
            }}
            className="flex w-full items-center gap-2 px-4 py-2 text-left text-sm text-rose-400 hover:bg-slate-700"
          >
            Delete
          </button>
        </div>
      )}
    </div>
  );
}

async function uploadImage(file: File): Promise<string> {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch("/api/admin/upload", { method: "POST", body: formData });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Upload failed");
  }
  const { url } = await res.json();
  return url;
}

const MATCH_TYPE_OPTIONS: { value: MatchType; label: string }[] = [
  { value: "solo", label: "Solo (1 player)" },
  { value: "duo", label: "Duo (2 players)" },
  { value: "squad", label: "Squad (4 players)" },
];

function MatchTypeDropdown({ value, onChange }: { value: MatchType; onChange: (v: MatchType) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("click", h);
    return () => document.removeEventListener("click", h);
  }, []);
  const label = MATCH_TYPE_OPTIONS.find((o) => o.value === value)?.label ?? value;
  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="admin-input flex w-full items-center justify-between rounded-xl px-4 py-3 text-left text-white outline-none"
      >
        <span>{label}</span>
        <svg className={`h-5 w-5 text-slate-400 transition ${open ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="absolute top-full left-0 right-0 z-50 mt-1 rounded-xl border border-slate-600/50 bg-slate-800 py-1 shadow-xl">
          {MATCH_TYPE_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              onClick={() => {
                onChange(opt.value);
                setOpen(false);
              }}
              className={`block w-full px-4 py-2.5 text-left text-slate-200 hover:bg-slate-700/80 ${opt.value === value ? "bg-slate-700/50 text-white" : ""}`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function ImageUpload({
  file,
  previewUrl,
  onChange,
  onClear,
}: {
  file: File | null;
  previewUrl: string | null;
  onChange: (file: File) => void;
  onClear: () => void;
}) {
  const inputId = `img-upload-${Math.random().toString(36).slice(2)}`;
  return (
    <div className="space-y-2">
      <label className="mb-2 block text-sm font-medium text-slate-300">Image (optional)</label>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
        <label
          htmlFor={inputId}
          className="admin-input flex min-h-[120px] cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-4 py-6 transition hover:border-orange-500/50"
        >
          <input
            id={inputId}
            type="file"
            accept="image/jpeg,image/png,image/gif,image/webp"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) onChange(f);
            }}
          />
          {previewUrl ? (
            <img src={previewUrl} alt="Preview" className="mb-2 max-h-24 rounded-lg object-cover" />
          ) : (
            <svg className="mb-2 h-10 w-10 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
          )}
          <span className="text-sm text-slate-400">
            {file ? file.name : "Click to upload or drag image"}
          </span>
        </label>
        {file && (
          <button
            type="button"
            onClick={onClear}
            className="rounded-lg bg-slate-700/50 px-4 py-2 text-sm text-slate-300 hover:bg-slate-600/50"
          >
            Remove
          </button>
        )}
      </div>
    </div>
  );
}

function GamesSection({
  games,
  onSelectGame,
  onSuccess,
  showCreateGame = true,
}: {
  games: Game[];
  onSelectGame: (id: string) => void;
  onSuccess: () => void;
  showCreateGame?: boolean;
}) {
  const [name, setName] = useState("");
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleImageChange = (file: File) => {
    setImageFile(file);
    setImagePreview(URL.createObjectURL(file));
  };

  const handleImageClear = () => {
    setImageFile(null);
    if (imagePreview) URL.revokeObjectURL(imagePreview);
    setImagePreview(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      let imageUrl: string | null = null;
      if (imageFile) {
        try {
          imageUrl = await uploadImage(imageFile);
        } catch (uploadErr) {
          console.warn("Image upload failed, adding game without image:", uploadErr);
        }
      }
      const res = await fetch("/api/admin/games", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, imageUrl }),
      });
      if (!res.ok) throw new Error(await res.text());
      setName("");
      handleImageClear();
      onSuccess();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to create game");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-8">
      {showCreateGame && (
        <section className="admin-card rounded-2xl p-6 sm:p-8">
          <h2 className="mb-1 text-base font-semibold text-white/90">Create Game</h2>
          <p className="mb-6 text-sm text-slate-400">Add a new game to the platform</p>
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
                placeholder="e.g. BGMI"
              />
            </div>
            <ImageUpload
              file={imageFile}
              previewUrl={imagePreview}
              onChange={handleImageChange}
              onClear={handleImageClear}
            />
            <button
              type="submit"
              disabled={submitting}
              className="admin-btn-primary rounded-xl px-6 py-3 font-medium text-white disabled:opacity-50"
            >
              {submitting ? "Creating..." : "Create Game"}
            </button>
          </form>
        </section>
      )}
      <section className="admin-card rounded-2xl p-6 sm:p-8">
        <h2 className="mb-1 text-base font-semibold text-white/90">Existing Games</h2>
        <p className="mb-5 text-sm text-slate-400">Click a game to manage modes and matches</p>
        <ul className="space-y-2">
          {games.map((g) => (
            <li
              key={g.id}
              role="button"
              tabIndex={0}
              onClick={() => onSelectGame(g.id)}
              onKeyDown={(e) => e.key === "Enter" && onSelectGame(g.id)}
              className="admin-list-item flex cursor-pointer items-center justify-between gap-2 rounded-xl px-4 py-3.5 transition hover:border-orange-500/30"
            >
              <span className="font-medium text-slate-200">{g.name}</span>
              <ItemMenu
                currentName={g.name}
                onDelete={async () => {
                  try {
                    const res = await fetch(`/api/admin/games/${g.id}`, { method: "DELETE" });
                    if (!res.ok) throw new Error(await res.text());
                    onSuccess();
                  } catch (err) {
                    alert(err instanceof Error ? err.message : "Failed to delete game");
                  }
                }}
                onRename={async (newName) => {
                  try {
                    const res = await fetch(`/api/admin/games/${g.id}`, {
                      method: "PATCH",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ name: newName }),
                    });
                    if (!res.ok) throw new Error(await res.text());
                    onSuccess();
                  } catch (err) {
                    alert(err instanceof Error ? err.message : "Failed to rename game");
                  }
                }}
              />
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function ModesSection({
  games,
  modes,
  gameId,
  onBack,
  onSelectMode,
  onSuccess,
}: {
  games: Game[];
  modes: GameMode[];
  gameId: string;
  onBack: (() => void) | undefined;
  onSelectMode: (id: string) => void;
  onSuccess: () => void;
}) {
  const [name, setName] = useState("");
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const gameName = games.find((g) => g.id === gameId)?.name ?? "Game";

  const handleImageChange = (file: File) => {
    setImageFile(file);
    setImagePreview(URL.createObjectURL(file));
  };

  const handleImageClear = () => {
    setImageFile(null);
    if (imagePreview) URL.revokeObjectURL(imagePreview);
    setImagePreview(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      let imageUrl: string | null = null;
      if (imageFile) {
        imageUrl = await uploadImage(imageFile);
      }
      const res = await fetch("/api/admin/modes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ gameId, name, imageUrl }),
      });
      if (!res.ok) throw new Error(await res.text());
      setName("");
      handleImageClear();
      onSuccess();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to create mode");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteMode = async (id: string) => {
    try {
      const res = await fetch(`/api/admin/modes/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error(await res.text());
      onSuccess();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete mode");
    }
  };

  const handleRenameMode = async (id: string, newName: string) => {
    try {
      const res = await fetch(`/api/admin/modes/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newName }),
      });
      if (!res.ok) throw new Error(await res.text());
      onSuccess();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to rename mode");
    }
  };

  return (
    <div className="space-y-8">
      {onBack && (
        <button
          type="button"
          onClick={onBack}
          className="flex items-center gap-2 text-sm text-slate-400 transition hover:text-white"
        >
          ← Back to Games
        </button>
      )}
      <section className="admin-card rounded-2xl p-6 sm:p-8">
        <h2 className="mb-1 text-base font-semibold text-white/90">Modes for {gameName}</h2>
        <p className="mb-6 text-sm text-slate-400">Create a new mode or click one to manage matches</p>
        <form onSubmit={handleSubmit} className="mb-6 space-y-5">
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-300">Mode Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
              placeholder="e.g. Ranked, Classic"
            />
          </div>
          <ImageUpload
            file={imageFile}
            previewUrl={imagePreview}
            onChange={handleImageChange}
            onClear={handleImageClear}
          />
          <button
            type="submit"
            disabled={submitting}
            className="admin-btn-primary rounded-xl px-6 py-3 font-medium text-white disabled:opacity-50"
          >
            {submitting ? "Creating..." : "Create Mode"}
          </button>
        </form>
        <h3 className="mb-3 text-sm font-medium text-slate-300">Existing Modes</h3>
        <ul className="space-y-2">
          {modes.map((m) => (
            <li
              key={m.id}
              role="button"
              tabIndex={0}
              onClick={() => onSelectMode(m.id)}
              onKeyDown={(e) => e.key === "Enter" && onSelectMode(m.id)}
              className="admin-list-item flex cursor-pointer items-center justify-between gap-2 rounded-xl px-4 py-3.5 transition hover:border-orange-500/30"
            >
              <span className="font-medium text-slate-200">{m.name}</span>
              <ItemMenu
                currentName={m.name}
                onDelete={() => handleDeleteMode(m.id)}
                onRename={(newName) => handleRenameMode(m.id, newName)}
              />
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

type ParticipantWithStats = {
  id: string;
  userId: string;
  teamMembers: { inGameName: string; inGameUid: string; kills?: number }[];
  rank?: number;
};
type MatchWithParticipants = Match & { participants?: ParticipantWithStats[] };

function calcCoinsForPosition(
  position: number,
  totalKills: number,
  prizePool: PrizePool | undefined
): number {
  if (!prizePool) return 0;
  let coins = totalKills * (prizePool.coinsPerKill ?? 0);
  const rewards = prizePool.rankRewards ?? [];
  for (const r of rewards) {
    if (position >= r.fromRank && position <= r.toRank) {
      coins += r.coins;
      break;
    }
  }
  return coins;
}

function MatchesSection({
  games,
  modes,
  matches,
  modeId,
  users,
  onBack,
  onSuccess,
}: {
  games: Game[];
  modes: GameMode[];
  matches: Match[];
  modeId: string;
  users: User[];
  onBack: () => void;
  onSuccess: (opts?: { silent?: boolean }) => void;
}) {
  const [title, setTitle] = useState("");
  const [entryFee, setEntryFee] = useState("");
  const [maxParticipants, setMaxParticipants] = useState("16");
  const [scheduledAt, setScheduledAt] = useState("");
  const [matchType, setMatchType] = useState<MatchType>("solo");
  const [coinsPerKill, setCoinsPerKill] = useState("5");
  const [totalPrizePool, setTotalPrizePool] = useState("");
  const [rankRewards, setRankRewards] = useState<RankReward[]>([{ fromRank: 1, toRank: 5, coins: 30 }]);
  const [submitting, setSubmitting] = useState(false);
  const [selectedMatchId, setSelectedMatchId] = useState<string | null>(null);
  const [matchTab, setMatchTab] = useState<"upcoming" | "ongoing" | "finished">("upcoming");

  const mode = modes.find((m) => m.id === modeId);
  const gameName = mode ? games.find((g) => g.id === mode.gameId)?.name ?? "?" : "?";
  const modeName = mode?.name ?? "?";

  const upcoming = matches.filter((m) => m.status === "upcoming");
  const ongoing = matches.filter((m) => m.status === "ongoing");
  const finished = matches.filter((m) => m.status === "ended" || m.status === "completed" || m.status === "cancelled");
  const tabMatches = matchTab === "upcoming" ? upcoming : matchTab === "ongoing" ? ongoing : finished;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await fetch("/api/admin/matches", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          gameModeId: modeId,
          title,
          entryFee: Number(entryFee),
          maxParticipants: Number(maxParticipants) || 16,
          scheduledAt: scheduledAt || new Date().toISOString(),
          matchType,
          prizePool: {
            coinsPerKill: Number(coinsPerKill) || 0,
            totalPrizePool: totalPrizePool ? Number(totalPrizePool) : 0,
            rankRewards: rankRewards.filter((r) => r.fromRank > 0 && r.toRank >= r.fromRank && r.coins >= 0),
          },
        }),
      });
      if (!res.ok) {
        const text = await res.text();
        let errMsg = "Failed to create match";
        try {
          const errData = JSON.parse(text);
          if (errData?.error) errMsg = errData.error;
        } catch {
          if (text) errMsg = text;
        }
        throw new Error(errMsg);
      }
      const data = await res.json();
      setTitle("");
      setEntryFee("");
      setMaxParticipants("16");
      setScheduledAt("");
      setMatchType("solo");
      setCoinsPerKill("5");
      setTotalPrizePool("");
      setRankRewards([{ fromRank: 1, toRank: 5, coins: 30 }]);
      setSelectedMatchId(data?.id ?? null);
      setMatchTab("upcoming");
      onSuccess();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to create match");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-8">
      <button
        type="button"
        onClick={onBack}
        className="flex items-center gap-2 text-sm text-slate-400 transition hover:text-white"
      >
        ← Back to Modes
      </button>
      <section className="admin-card rounded-2xl p-6 sm:p-8">
        <h2 className="mb-1 text-base font-semibold text-white/90">Matches for {gameName} → {modeName}</h2>
        <p className="mb-6 text-sm text-slate-400">Create matches and manage ongoing/upcoming</p>
        <form onSubmit={handleSubmit} className="mb-8 space-y-5">
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-300">Title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
              className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
              placeholder="e.g. Weekend Cup #1"
            />
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-300">Match Type</label>
            <MatchTypeDropdown value={matchType} onChange={setMatchType} />
          </div>
          <div className="grid gap-5 sm:grid-cols-2">
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">Entry Fee (coins)</label>
              <input
                type="number"
                min="0"
                value={entryFee}
                onChange={(e) => setEntryFee(e.target.value)}
                required
                className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
                placeholder="50"
              />
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">Max Participants</label>
              <input
                type="number"
                min="2"
                value={maxParticipants}
                onChange={(e) => setMaxParticipants(e.target.value)}
                className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
              />
            </div>
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-300">Scheduled At (optional)</label>
            <input
              type="datetime-local"
              value={scheduledAt}
              onChange={(e) => setScheduledAt(e.target.value)}
              className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
            />
          </div>
          <div className="rounded-xl border border-slate-600/50 bg-slate-800/30 p-5">
            <h3 className="mb-3 text-sm font-medium text-slate-300">Prize Pool</h3>
            <div className="mb-4 grid gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs text-slate-400">Total prize pool (coins)</label>
                <input
                  type="number"
                  min="0"
                  value={totalPrizePool}
                  onChange={(e) => setTotalPrizePool(e.target.value)}
                  className="admin-input w-full rounded-lg px-4 py-2.5 text-sm text-white outline-none"
                  placeholder="e.g. 500"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-slate-400">Coins per kill</label>
                <input
                  type="number"
                  min="0"
                  value={coinsPerKill}
                  onChange={(e) => setCoinsPerKill(e.target.value)}
                  className="admin-input w-full rounded-lg px-4 py-2.5 text-sm text-white outline-none"
                  placeholder="5"
                />
              </div>
            </div>
            <div className="space-y-3">
              <label className="block text-xs text-slate-400">Rank rewards (coins per rank range)</label>
              {rankRewards.map((r, i) => (
                <div key={i} className="flex flex-wrap items-center gap-2">
                  <input
                    type="number"
                    min="1"
                    value={r.fromRank}
                    onChange={(e) =>
                      setRankRewards((prev) =>
                        prev.map((x, j) => (j === i ? { ...x, fromRank: Number(e.target.value) || 1 } : x))
                      )
                    }
                    className="admin-input w-16 rounded-lg px-3 py-2 text-sm text-white outline-none"
                  />
                  <span className="text-slate-500">-</span>
                  <input
                    type="number"
                    min="1"
                    value={r.toRank}
                    onChange={(e) =>
                      setRankRewards((prev) =>
                        prev.map((x, j) => (j === i ? { ...x, toRank: Number(e.target.value) || 1 } : x))
                      )
                    }
                    className="admin-input w-16 rounded-lg px-3 py-2 text-sm text-white outline-none"
                  />
                  <span className="text-slate-500">→</span>
                  <input
                    type="number"
                    min="0"
                    value={r.coins}
                    onChange={(e) =>
                      setRankRewards((prev) =>
                        prev.map((x, j) => (j === i ? { ...x, coins: Number(e.target.value) || 0 } : x))
                      )
                    }
                    className="admin-input w-20 rounded-lg px-3 py-2 text-sm text-white outline-none"
                    placeholder="coins"
                  />
                  <span className="text-slate-400 text-sm">coins</span>
                  <button
                    type="button"
                    onClick={() => setRankRewards((prev) => prev.filter((_, j) => j !== i))}
                    className="rounded p-1.5 text-rose-400 hover:bg-rose-500/20"
                    aria-label="Remove"
                  >
                    <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </div>
              ))}
              <button
                type="button"
                onClick={() =>
                  setRankRewards((prev) => {
                    const maxTo = Math.max(0, ...prev.map((r) => r.toRank));
                    return [...prev, { fromRank: maxTo + 1, toRank: maxTo + 5, coins: 10 }];
                  })
                }
                className="rounded-lg border border-dashed border-slate-500 px-3 py-2 text-sm text-slate-400 hover:border-orange-500/50 hover:text-orange-400"
              >
                + Add rank range
              </button>
            </div>
          </div>
          <button
            type="submit"
            disabled={submitting}
            className="admin-btn-primary rounded-xl px-6 py-3 font-medium text-white disabled:opacity-50"
          >
            {submitting ? "Creating..." : "Create Match"}
          </button>
        </form>

        <div className="mb-6 grid w-full grid-cols-3 gap-2 sm:flex">
          {(["upcoming", "ongoing", "finished"] as const).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => { setMatchTab(t); setSelectedMatchId(null); }}
              className={`rounded-full px-3 py-2 text-xs font-medium sm:px-4 sm:text-sm ${
                matchTab === t
                  ? "bg-orange-500/80 text-white"
                  : "bg-slate-700/50 text-slate-400 hover:bg-slate-600/50"
              }`}
            >
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>

        {selectedMatchId ? (
          <MatchDetailView
            matchId={selectedMatchId}
            games={games}
            modes={modes}
            users={users}
            onBack={() => setSelectedMatchId(null)}
            onSuccess={onSuccess}
          />
        ) : (
          <ul className="space-y-2">
            {tabMatches.map((m) => (
              <li
                key={m.id}
                role="button"
                tabIndex={0}
                onClick={() => setSelectedMatchId(m.id)}
                onKeyDown={(e) => e.key === "Enter" && setSelectedMatchId(m.id)}
                className="admin-list-item flex cursor-pointer flex-wrap items-center justify-between gap-2 rounded-xl px-4 py-3.5 transition hover:border-orange-500/30"
              >
                <span className="text-slate-200">
                  {m.title}
                  <span className="ml-2 text-amber-400/90">→ {m.entryFee} coins</span>
                  {m.matchType && (
                    <span className="ml-2 rounded bg-slate-600/50 px-2 py-0.5 text-xs text-slate-400">
                      {m.matchType}
                    </span>
                  )}
                  {((m.prizePool?.totalPrizePool ?? 0) > 0 || (m.prizePool?.coinsPerKill ?? 0) > 0) && (
                    <span className="ml-2 block text-xs">
                      {(m.prizePool?.totalPrizePool ?? 0) > 0 && (
                        <span className="text-emerald-400/90 block">{m.prizePool?.totalPrizePool} prizepool</span>
                      )}
                      {(m.prizePool?.coinsPerKill ?? 0) > 0 && (
                        <span className="text-slate-400 block">{m.prizePool?.coinsPerKill} coins/kill</span>
                      )}
                    </span>
                  )}
                </span>
                <span
                  className={`rounded-lg px-4 py-1.5 text-xs font-medium ${
                    m.status === "ongoing"
                      ? "bg-emerald-500/20 text-emerald-300"
                      : m.status === "cancelled"
                        ? "bg-rose-500/20 text-rose-300"
                        : m.status === "ended" || m.status === "completed"
                          ? "bg-slate-600/30 text-slate-400"
                          : "bg-amber-500/20 text-amber-300"
                  }`}
                >
                  {m.status}
                </span>
              </li>
            ))}
            {tabMatches.length === 0 && (
              <li className="rounded-xl border border-slate-600/50 bg-slate-800/30 px-4 py-8 text-center text-slate-400">
                No {matchTab} matches
              </li>
            )}
          </ul>
        )}
      </section>
    </div>
  );
}

function MatchDetailView({
  matchId,
  games,
  modes,
  users,
  onBack,
  onSuccess,
}: {
  matchId: string;
  games: Game[];
  modes: GameMode[];
  users: User[];
  onBack: () => void;
  onSuccess: (opts?: { silent?: boolean }) => void;
}) {
  const [match, setMatch] = useState<MatchWithParticipants | null>(null);
  const [loading, setLoading] = useState(true);
  const [roomCode, setRoomCode] = useState("");
  const [roomPassword, setRoomPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [starting, setStarting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [finishing, setFinishing] = useState(false);
  const [updatingParticipant, setUpdatingParticipant] = useState<string | null>(null);
  const [localKills, setLocalKills] = useState<Record<string, number[]>>({});
  const [localRank, setLocalRank] = useState<Record<string, number | "">>({});

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/admin/matches/${matchId}`)
      .then((r) => r.json())
      .then((data) => {
        if (!cancelled) {
          setMatch(data);
          setRoomCode(data.roomCode ?? "");
          setRoomPassword(data.roomPassword ?? "");
        }
      })
      .catch(() => setMatch(null))
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [matchId]);

  useEffect(() => {
    if (!match?.participants) return;
    const nextKills: Record<string, number[]> = {};
    const nextRank: Record<string, number | ""> = {};
    for (const p of match.participants) {
      nextKills[p.id] = (p.teamMembers ?? []).map((t) => t.kills ?? 0);
      nextRank[p.id] = p.rank ?? "";
    }
    setLocalKills((prev) => ({ ...prev, ...nextKills }));
    setLocalRank((prev) => ({ ...prev, ...nextRank }));
  }, [match]);

  const mode = modes.find((m) => m.id === match?.gameModeId);
  const gameName = mode ? games.find((g) => g.id === mode.gameId)?.name ?? "?" : "?";

  const handleSaveRoom = async () => {
    setSaving(true);
    try {
      const res = await fetch(`/api/admin/matches/${matchId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ roomCode, roomPassword }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setMatch(data);
      onSuccess({ silent: true });
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to save room info");
    } finally {
      setSaving(false);
    }
  };

  const handleStart = async () => {
    setStarting(true);
    try {
      const res = await fetch(`/api/admin/matches/${matchId}/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ roomCode, roomPassword }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || "Failed to start match");
      }
      const data = await res.json();
      setMatch(data);
      onSuccess({ silent: true });
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to start match");
    } finally {
      setStarting(false);
    }
  };

  const handleCancel = async () => {
    if (!confirm("Cancel this match? All registered players will receive a refund.")) return;
    setCancelling(true);
    try {
      const res = await fetch(`/api/admin/matches/${matchId}/cancel`, { method: "POST" });
      if (!res.ok) throw new Error(await res.text());
      setMatch(null);
      onBack();
      onSuccess({ silent: true });
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to cancel match");
    } finally {
      setCancelling(false);
    }
  };

  const handleFinish = async () => {
    if (!match) return;
    const allUpdated = (match.participants ?? []).every(
      (p) =>
        (typeof p.rank === "number" && p.rank >= 1) ||
        (p.teamMembers ?? []).some((t) => (t.kills ?? 0) > 0)
    );
    if (!allUpdated && (match.participants ?? []).length > 0) {
      alert("Update rank and kills for all participants before finishing the match.");
      return;
    }
    if (!confirm("Finish this match? Coins will be transferred to winners. This cannot be undone.")) return;
    setFinishing(true);
    try {
      const res = await fetch(`/api/admin/matches/${matchId}/finish`, { method: "POST" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || "Failed to finish match");
      }
      const data = await res.json();
      setMatch(data);
      onSuccess({ silent: true });
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to finish match");
    } finally {
      setFinishing(false);
    }
  };

  if (loading || !match) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingSpinner size="md" compact label="Loading match..." />
      </div>
    );
  }

  const participants = match.participants ?? [];
  const isUpcoming = match.status === "upcoming";
  const isOngoing = match.status === "ongoing";
  const hasRoomInfo = !!(match.roomCode && match.roomPassword);
  const canStartMatch = hasRoomInfo || (!!roomCode && !!roomPassword);
  const getKills = (p: ParticipantWithStats) =>
    localKills[p.id] ?? (p.teamMembers ?? []).map((t) => t.kills ?? 0);

  const handleUpdateParticipant = async (p: ParticipantWithStats) => {
    setUpdatingParticipant(p.id);
    try {
      const kills = localKills[p.id] ?? (p.teamMembers ?? []).map((t) => t.kills ?? 0);
      const rankVal = localRank[p.id];
      const body: { kills?: number[]; rank?: number } = {};
      const serverKills = (p.teamMembers ?? []).map((t) => t.kills ?? 0);
      if (JSON.stringify(kills) !== JSON.stringify(serverKills)) body.kills = kills;
      if (typeof rankVal === "number" && rankVal >= 1 && rankVal !== p.rank) body.rank = rankVal;
      if (Object.keys(body).length === 0) return;
      const res = await fetch(`/api/admin/matches/${matchId}/participants/${p.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setMatch(data);
      onSuccess({ silent: true });
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to update");
    } finally {
      setUpdatingParticipant(null);
    }
  };

  return (
    <div className="space-y-6">
      <button
        type="button"
        onClick={onBack}
        className="flex items-center gap-2 text-sm text-slate-400 transition hover:text-white"
      >
        ← Back to matches
      </button>

      <div className="rounded-xl border border-slate-600/50 bg-slate-800/30 p-6">
        <h2 className="text-lg font-semibold text-white">{match.title}</h2>
        <div className="mt-2 flex flex-wrap gap-2">
          <span className={`rounded-lg px-3 py-1 text-xs font-medium ${
            match.status === "ongoing" ? "bg-emerald-500/20 text-emerald-300" :
            match.status === "cancelled" ? "bg-rose-500/20 text-rose-300" :
            match.status === "ended" || match.status === "completed" ? "bg-slate-600/30 text-slate-400" :
            "bg-amber-500/20 text-amber-300"
          }`}>
            {match.status}
          </span>
          <span className="rounded bg-slate-600/50 px-3 py-1 text-xs text-slate-400">{match.matchType}</span>
          <span className="rounded bg-slate-600/50 px-3 py-1 text-xs text-amber-400">{match.entryFee} coins</span>
        </div>
        <p className="mt-2 text-sm text-slate-400">
          {gameName} • Scheduled: {match.scheduledAt ? new Date(match.scheduledAt).toLocaleString() : "TBD"}
        </p>
      </div>

      <div className="rounded-xl border border-slate-600/50 bg-slate-800/30 p-6">
        <h3 className="mb-3 text-sm font-medium text-slate-300">Prize Pool</h3>
        <div className="space-y-2 text-sm">
          <p className="text-slate-200">Coins per kill: {match.prizePool?.coinsPerKill ?? 0}</p>
          {(match.prizePool?.rankRewards ?? []).map((r: RankReward, i: number) => (
            <p key={i} className="text-slate-200">
              Rank {r.fromRank}-{r.toRank}: {r.coins} coins
            </p>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-slate-600/50 bg-slate-800/30 p-4 sm:p-6">
        <div className="mb-3 flex flex-col gap-1 sm:flex-row sm:items-baseline">
          <h3 className="text-sm font-medium text-slate-300">
            Players Joined ({participants.length})
          </h3>
          {isOngoing && (
            <span className="text-xs font-normal text-emerald-400">
              Edit kills/rank, then click Update to save. Changes apply only after Update.
            </span>
          )}
        </div>
        {participants.length === 0 ? (
          <p className="text-sm text-slate-400">No players registered yet</p>
        ) : (
          <ul className="space-y-3">
            {participants.map((p, i) => {
              const killsArr = getKills(p);
              const totalKills = killsArr.reduce((sum, k) => sum + k, 0);
              const rankVal = localRank[p.id] ?? "";
              const serverKills = (p.teamMembers ?? []).map((t) => t.kills ?? 0);
              const killsChanged = JSON.stringify(killsArr) !== JSON.stringify(serverKills);
              const rankChanged = typeof rankVal === "number" && rankVal >= 1 && rankVal !== p.rank;
              const hasChanges = killsChanged || rankChanged;
              const hasBeenUpdated =
                (typeof p.rank === "number" && p.rank >= 1) ||
                (p.teamMembers ?? []).some((t) => (t.kills ?? 0) > 0);
              const position = typeof p.rank === "number" && p.rank >= 1 ? p.rank : i + 1;
              const coins = calcCoinsForPosition(position, totalKills, match.prizePool);
              return (
                <li
                  key={p.id}
                  className="flex flex-col gap-3 rounded-lg bg-slate-700/30 p-4 transition sm:flex-row sm:flex-wrap sm:items-center sm:gap-3"
                >
                  {hasBeenUpdated && (
                    <span className="shrink-0 text-sm font-bold text-slate-400">#{position}</span>
                  )}
                  <div className="min-w-0 flex-1 space-y-2">
                    {p.userId && (
                      <div className="break-all text-xs font-mono text-slate-500">
                        User ID: {p.userId}
                      </div>
                    )}
                    {(p.teamMembers ?? []).map((t, ti) => (
                      <div key={ti} className="flex flex-wrap items-center gap-2">
                        <div>
                          <div className="text-base font-bold text-white">{t.inGameName}</div>
                          <div className="text-xs opacity-60 text-slate-400">{t.inGameUid}</div>
                        </div>
                        {isOngoing && (
                          <div className="flex items-center gap-1">
                            <label className="text-xs text-slate-500">Kills</label>
                            <input
                              type="number"
                              min={0}
                              value={killsArr[ti] ?? 0}
                              onChange={(e) => {
                                const v = Number(e.target.value) || 0;
                                setLocalKills((prev) => ({
                                  ...prev,
                                  [p.id]: (prev[p.id] ?? killsArr).map((k, j) => (j === ti ? v : k)),
                                }));
                              }}
                              className="admin-input w-14 rounded-lg px-2 py-1.5 text-center text-sm"
                            />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                  {isOngoing && (
                    <>
                      <div className="flex items-center gap-1">
                        <label className="text-xs text-slate-500">Rank</label>
                        <input
                          type="number"
                          min={1}
                          max={participants.length}
                          value={rankVal === "" ? "" : rankVal}
                          onChange={(e) => {
                            const v = e.target.value;
                            setLocalRank((prev) => ({
                              ...prev,
                              [p.id]: v === "" ? "" : Math.min(participants.length, Math.max(1, Number(v) || 1)),
                            }));
                          }}
                          placeholder="—"
                          className="admin-input w-14 rounded-lg px-2 py-1.5 text-center text-sm"
                        />
                      </div>
                      {hasChanges && (
                        <button
                          type="button"
                          onClick={() => handleUpdateParticipant(p)}
                          disabled={!!updatingParticipant}
                          className="shrink-0 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
                        >
                          {updatingParticipant === p.id ? "Updating..." : "Update"}
                        </button>
                      )}
                    </>
                  )}
                  {hasBeenUpdated && (
                    <span className="shrink-0 self-start rounded-lg bg-amber-500/20 px-3 py-1 font-medium text-amber-300 sm:self-center">
                      {coins} coins
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {isOngoing && (
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-6">
          <h3 className="mb-4 text-sm font-medium text-emerald-200">Finish Match</h3>
          <p className="mb-4 text-xs text-slate-400">
            After updating rank and kills for all participants, click Finish to complete the match. Coins will be transferred to winners.
          </p>
          <button
            type="button"
            onClick={handleFinish}
            disabled={finishing}
            className="rounded-xl bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            {finishing ? "Finishing..." : "Finish Match"}
          </button>
        </div>
      )}

      {isUpcoming && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-6">
          <h3 className="mb-4 text-sm font-medium text-amber-200">Room Info</h3>
          <p className="mb-4 text-xs text-slate-400">
            Set room code and password. Registered players will be notified when updated. Only they can see it.
          </p>
          <div className="mb-4 grid gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs text-slate-400">Room Code</label>
              <input
                type="text"
                value={roomCode}
                onChange={(e) => setRoomCode(e.target.value)}
                className="admin-input w-full rounded-lg px-4 py-2.5 text-sm text-white outline-none"
                placeholder="ROOM123"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-slate-400">Room Password</label>
              <input
                type="text"
                value={roomPassword}
                onChange={(e) => setRoomPassword(e.target.value)}
                className="admin-input w-full rounded-lg px-4 py-2.5 text-sm text-white outline-none"
                placeholder="pass123"
              />
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              onClick={handleSaveRoom}
              disabled={saving}
              className="rounded-xl bg-slate-600 px-4 py-2 text-sm font-medium text-white hover:bg-slate-500 disabled:opacity-50"
            >
              {saving ? "Saving..." : "Save Room Info"}
            </button>
            {canStartMatch && (
              <button
                type="button"
                onClick={handleStart}
                disabled={starting}
                className="rounded-xl bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
              >
                {starting ? "Starting..." : "Start Match"}
              </button>
            )}
            <button
              type="button"
              onClick={handleCancel}
              disabled={cancelling}
              className="rounded-xl bg-rose-600 px-4 py-2 text-sm font-medium text-white hover:bg-rose-500 disabled:opacity-50"
            >
              {cancelling ? "Cancelling..." : "Cancel Match"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

type AdminListItem = {
  id: string;
  adminname: string;
  isMasterAdmin: boolean;
  usersAccess: boolean;
  coinsAccess: boolean;
  gamesAccessType: string;
  allowedGameIds: string[];
};

function AdminProfileModal({
  admin,
  games,
  onClose,
  onDelete,
}: {
  admin: AdminListItem;
  games: Game[];
  onClose: () => void;
  onDelete: () => void;
}) {
  const [newPassword, setNewPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("click", close);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("click", close);
      document.removeEventListener("keydown", esc);
    };
  }, [onClose]);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPassword || newPassword.length < 6) return;
    setSubmitting(true);
    try {
      const res = await fetch(`/api/admin/admins/${admin.id}/password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ newPassword }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to change password");
      }
      setNewPassword("");
      alert("Password updated successfully");
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to change password");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (admin.isMasterAdmin) return;
    if (!confirm("Are you sure you want to delete this admin? This cannot be undone.")) return;
    setDeleting(true);
    try {
      const res = await fetch(`/api/admin/admins/${admin.id}`, { method: "DELETE" });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to delete admin");
      }
      onDelete();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete admin");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center sm:items-center sm:p-4">
      <div
        className="absolute inset-0 bg-black/70"
        onClick={onClose}
        aria-hidden
      />
      <div
        ref={ref}
        className="relative z-10 w-full max-h-[90vh] sm:max-h-[calc(100vh-2rem)] sm:max-w-md overflow-y-auto rounded-t-2xl sm:rounded-2xl border border-slate-600/50 border-b-0 sm:border-b bg-slate-900 shadow-xl pb-[env(safe-area-inset-bottom)] sm:pb-0"
      >
        {/* Mobile: drag handle */}
        <div className="sticky top-0 z-10 flex flex-col bg-slate-900/95 backdrop-blur-sm sm:bg-slate-900 sm:backdrop-blur-none">
          <div className="flex justify-center pt-3 pb-1 sm:hidden">
            <div className="h-1 w-12 rounded-full bg-slate-600" aria-hidden />
          </div>
          <div className="flex items-center justify-between px-4 pb-4 pt-1 sm:px-6 sm:pt-6 sm:pb-0">
            <h2 className="text-base sm:text-lg font-semibold text-white">Admin Profile</h2>
            <button
              type="button"
              onClick={onClose}
              className="-mr-2 rounded-lg p-2.5 text-slate-400 transition hover:bg-white/10 hover:text-white touch-manipulation"
              aria-label="Close"
            >
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        <div className="px-4 pb-6 pt-0 sm:px-6 sm:pt-0 sm:pb-6">
          <dl className="space-y-4 sm:space-y-4">
            <div className="flex flex-col gap-1 sm:block">
              <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Admin Name</dt>
              <dd className="font-medium text-white break-words">{admin.adminname}</dd>
            </div>
            <div className="flex flex-col gap-1 sm:block">
              <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Admin ID</dt>
              <dd className="font-mono text-sm text-slate-400 break-all">{admin.id}</dd>
            </div>
            <div className="flex flex-col gap-1.5 sm:block">
              <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Role</dt>
              <dd>
                <span className={`inline-block rounded-lg px-2.5 py-1 text-xs font-medium ${admin.isMasterAdmin ? "bg-amber-500/20 text-amber-300" : "text-slate-300 bg-slate-600/50"}`}>
                  {admin.isMasterAdmin ? "Master Admin" : "Admin"}
                </span>
              </dd>
            </div>
            <div className="flex flex-col gap-1.5 sm:block">
              <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Permissions</dt>
              <dd className="flex flex-wrap gap-1.5">
                {admin.usersAccess && <span className="rounded bg-slate-600/50 px-2 py-0.5 text-xs text-slate-300">Users</span>}
                {admin.coinsAccess && <span className="rounded bg-slate-600/50 px-2 py-0.5 text-xs text-slate-300">Coins</span>}
                {admin.gamesAccessType === "all" ? (
                  <span className="rounded bg-slate-600/50 px-2 py-0.5 text-xs text-slate-300">All games</span>
                ) : (
                  (admin.allowedGameIds ?? []).map((gid) => {
                    const game = games.find((g) => g.id === gid);
                    return game ? (
                      <span key={gid} className="rounded bg-slate-600/50 px-2 py-0.5 text-xs text-slate-300">{game.name}</span>
                    ) : null;
                  })
                )}
              </dd>
            </div>
          </dl>

          <div className="mt-6 sm:mt-8 space-y-4 border-t border-slate-700/50 pt-6">
            <form onSubmit={handleChangePassword} className="flex flex-col gap-3 sm:flex-row sm:gap-2">
              <input
                type="password"
                minLength={6}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="New password (min 6 chars)"
                className="admin-input w-full flex-1 rounded-lg px-4 py-3 sm:py-2 text-sm min-h-[44px] sm:min-h-0"
              />
              <button
                type="submit"
                disabled={submitting || !newPassword || newPassword.length < 6}
                className="admin-btn-primary w-full sm:w-auto rounded-lg px-4 py-3 sm:py-2 text-sm font-medium disabled:opacity-50 min-h-[44px] sm:min-h-0 shrink-0"
              >
                {submitting ? "..." : "Change Password"}
              </button>
            </form>
            {!admin.isMasterAdmin && (
              <button
                type="button"
                onClick={handleDelete}
                disabled={deleting}
                className="w-full rounded-lg bg-red-600 px-4 py-3 sm:py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50 min-h-[44px] sm:min-h-0"
              >
                {deleting ? "..." : "Delete Admin"}
              </button>
            )}
            {admin.isMasterAdmin && (
              <p className="text-xs text-slate-500">Master admin cannot be deleted. Only password can be changed.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function CreateAdminSection({
  games,
  onSuccess,
}: {
  games: Game[];
  onSuccess: () => void;
}) {
  const [adminname, setAdminname] = useState("");
  const [password, setPassword] = useState("");
  const [usersAccess, setUsersAccess] = useState(false);
  const [coinsAccess, setCoinsAccess] = useState(false);
  const [gamesAccessType, setGamesAccessType] = useState<"all" | "specific">("all");
  const [allowedGameIds, setAllowedGameIds] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [admins, setAdmins] = useState<AdminListItem[]>([]);
  const [selectedAdmin, setSelectedAdmin] = useState<AdminListItem | null>(null);

  const refreshAdmins = useCallback(() => {
    fetch("/api/admin/admins")
      .then((r) => r.json())
      .then((data) => Array.isArray(data) && setAdmins(data))
      .catch(() => {});
  }, []);

  useEffect(() => {
    refreshAdmins();
  }, [refreshAdmins]);

  const toggleGame = (gameId: string) => {
    setAllowedGameIds((prev) =>
      prev.includes(gameId) ? prev.filter((id) => id !== gameId) : [...prev, gameId]
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const res = await fetch("/api/admin/admins", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          adminname,
          password,
          usersAccess,
          coinsAccess,
          gamesAccessType,
          allowedGameIds: gamesAccessType === "specific" ? allowedGameIds : [],
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Failed to create admin");
        return;
      }
      setAdminname("");
      setPassword("");
      setUsersAccess(false);
      setCoinsAccess(false);
      setGamesAccessType("all");
      setAllowedGameIds([]);
      refreshAdmins();
      onSuccess();
    } catch {
      setError("Failed to create admin");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-8">
      <section className="admin-card rounded-2xl p-6 sm:p-8">
        <h2 className="mb-1 text-base font-semibold text-white/90">Create Admin</h2>
        <p className="mb-6 text-sm text-slate-400">Create credentials for a new admin. Set permissions below.</p>
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-300">Admin Name</label>
            <input
              type="text"
              value={adminname}
              onChange={(e) => setAdminname(e.target.value)}
              required
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
              minLength={6}
              className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
              placeholder="••••••••"
            />
          </div>
          <div className="space-y-3">
            <label className="block text-sm font-medium text-slate-300">Permissions</label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={usersAccess}
                onChange={(e) => setUsersAccess(e.target.checked)}
                className="rounded border-slate-500"
              />
              <span className="text-slate-200">Users tab access</span>
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={coinsAccess}
                onChange={(e) => setCoinsAccess(e.target.checked)}
                className="rounded border-slate-500"
              />
              <span className="text-slate-200">Coins tab access</span>
            </label>
            <div className="pt-2">
              <span className="mb-2 block text-sm text-slate-400">Games access</span>
              <div className="flex gap-4">
                <label className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="gamesAccess"
                    checked={gamesAccessType === "all"}
                    onChange={() => setGamesAccessType("all")}
                    className="border-slate-500"
                  />
                  <span className="text-slate-200">All games</span>
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="gamesAccess"
                    checked={gamesAccessType === "specific"}
                    onChange={() => setGamesAccessType("specific")}
                    className="border-slate-500"
                  />
                  <span className="text-slate-200">Specific games</span>
                </label>
              </div>
              {gamesAccessType === "specific" && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {games.map((g) => (
                    <label
                      key={g.id}
                      className="flex cursor-pointer items-center gap-2 rounded-lg border border-slate-600 bg-slate-800/50 px-3 py-2 transition hover:border-orange-500/30"
                    >
                      <input
                        type="checkbox"
                        checked={allowedGameIds.includes(g.id)}
                        onChange={() => toggleGame(g.id)}
                        className="rounded border-slate-500"
                      />
                      <span className="text-sm text-slate-200">{g.name}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          </div>
          {error && <p className="rounded-lg bg-rose-500/20 px-4 py-2 text-sm text-rose-300">{error}</p>}
          <button
            type="submit"
            disabled={submitting}
            className="admin-btn-primary rounded-xl px-6 py-3 font-medium text-white disabled:opacity-50"
          >
            {submitting ? "Creating..." : "Create Admin"}
          </button>
        </form>
      </section>
      <section className="admin-card rounded-2xl p-6 sm:p-8">
        <h2 className="mb-1 text-base font-semibold text-white/90">Existing Admins</h2>
        <p className="mb-5 text-sm text-slate-400">{admins.length} admin(s)</p>
        <ul className="space-y-2">
          {admins.map((a) => (
            <li
              key={a.id}
              role="button"
              tabIndex={0}
              onClick={() => setSelectedAdmin(a)}
              onKeyDown={(e) => e.key === "Enter" && setSelectedAdmin(a)}
              className="admin-list-item flex cursor-pointer flex-col gap-2 rounded-xl px-4 py-3.5 transition hover:border-orange-500/30 sm:flex-row sm:items-center sm:justify-between"
            >
              <span className="shrink-0 font-medium text-slate-200">{a.adminname}</span>
              <div className="flex flex-wrap gap-1.5">
                {a.isMasterAdmin && (
                  <span className="shrink-0 rounded-lg bg-amber-500/20 px-2 py-0.5 text-xs text-amber-300">Master</span>
                )}
                {a.usersAccess && <span className="shrink-0 rounded bg-slate-600/50 px-2 py-0.5 text-xs text-slate-300">Users</span>}
                {a.coinsAccess && <span className="shrink-0 rounded bg-slate-600/50 px-2 py-0.5 text-xs text-slate-300">Coins</span>}
                {a.gamesAccessType === "all" ? (
                  <span className="shrink-0 rounded bg-slate-600/50 px-2 py-0.5 text-xs text-slate-300">All games</span>
                ) : (
                  (a.allowedGameIds ?? []).map((gid) => {
                    const game = games.find((g) => g.id === gid);
                    return game ? (
                      <span key={gid} className="shrink-0 rounded bg-slate-600/50 px-2 py-0.5 text-xs text-slate-300">
                        {game.name}
                      </span>
                    ) : null;
                  })
                )}
              </div>
            </li>
          ))}
        </ul>
      </section>
      {selectedAdmin && (
        <AdminProfileModal
          admin={selectedAdmin}
          games={games}
          onClose={() => setSelectedAdmin(null)}
          onDelete={() => {
            refreshAdmins();
            setSelectedAdmin(null);
          }}
        />
      )}
    </div>
  );
}

function UsersSection({
  users,
  canAddCoins,
  onSuccess,
}: {
  users: User[];
  canAddCoins: boolean;
  onSuccess: () => void;
}) {
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [usersTab, setUsersTab] = useState<"all" | "blocked">("all");
  const [signupBonus, setSignupBonus] = useState(0);
  const [signupBonusInput, setSignupBonusInput] = useState("");
  const [savingBonus, setSavingBonus] = useState(false);
  const [supportUrl, setSupportUrl] = useState("");
  const [supportUrlInput, setSupportUrlInput] = useState("");
  const [savingSupport, setSavingSupport] = useState(false);
  const filteredUsers = usersTab === "blocked" ? users.filter((u) => u.isBlocked) : users;

  const fetchSignupBonus = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/signup-bonus");
      if (res.ok) {
        const { signupBonus: bonus } = await res.json();
        setSignupBonus(bonus);
        setSignupBonusInput(String(bonus));
      }
    } catch {
      setSignupBonusInput("0");
    }
  }, []);

  const fetchSupportUrl = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/customer-support");
      if (res.ok) {
        const { url } = await res.json();
        setSupportUrl(url || "");
        setSupportUrlInput(url || "");
      }
    } catch {
      setSupportUrlInput("");
    }
  }, []);

  useEffect(() => {
    fetchSignupBonus();
  }, [fetchSignupBonus]);

  useEffect(() => {
    fetchSupportUrl();
  }, [fetchSupportUrl]);

  const handleSaveSignupBonus = async () => {
    const num = Number(signupBonusInput);
    if (isNaN(num) || num < 0) {
      alert("Enter a valid amount (0 or greater)");
      return;
    }
    setSavingBonus(true);
    try {
      const res = await fetch("/api/admin/signup-bonus", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ signupBonus: num }),
      });
      if (!res.ok) throw new Error(await res.text());
      const { signupBonus: bonus } = await res.json();
      setSignupBonus(bonus);
      setSignupBonusInput(String(bonus));
      onSuccess();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSavingBonus(false);
    }
  };

  const handleSaveSupportUrl = async () => {
    const trimmed = supportUrlInput.trim();
    setSavingSupport(true);
    try {
      const res = await fetch("/api/admin/customer-support", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmed || null }),
      });
      if (!res.ok) throw new Error(await res.text());
      const { url } = await res.json();
      setSupportUrl(url || "");
      setSupportUrlInput(url || "");
      onSuccess();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSavingSupport(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="admin-card rounded-2xl p-6 sm:p-8">
        <h3 className="mb-2 text-sm font-medium text-slate-300">Customer Support Button</h3>
        <p className="mb-4 text-xs text-slate-400">
          The &quot;Support&quot; button in the user app header will link here. Use WhatsApp (e.g. https://wa.me/919876543210), Telegram (e.g. https://t.me/yourusername), or any URL. Leave empty to hide the button.
        </p>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-4">
          <input
            type="url"
            value={supportUrlInput}
            onChange={(e) => setSupportUrlInput(e.target.value)}
            placeholder="https://wa.me/919876543210 or https://t.me/username"
            className="admin-input min-w-0 flex-1 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500"
          />
          <button
            type="button"
            onClick={handleSaveSupportUrl}
            disabled={savingSupport}
            className="rounded-lg bg-orange-600 px-4 py-2 text-sm font-medium text-white hover:bg-orange-500 disabled:opacity-50"
          >
            {savingSupport ? "Saving..." : "Save"}
          </button>
        </div>
      </section>
      <section className="admin-card rounded-2xl p-6 sm:p-8">
        <h3 className="mb-2 text-sm font-medium text-slate-300">Signup Bonus</h3>
        <p className="mb-4 text-xs text-slate-400">
          New accounts registered after saving will receive this many coins with note &quot;Signup bonus&quot;.
        </p>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-4">
          <div className="flex items-center gap-2">
            <input
              type="number"
              min="0"
              value={signupBonusInput}
              onChange={(e) => setSignupBonusInput(e.target.value)}
              placeholder="0"
              className="admin-input w-24 rounded-lg px-3 py-2 text-sm text-white"
            />
            <span className="text-sm text-slate-400">coins</span>
          </div>
          <button
            type="button"
            onClick={handleSaveSignupBonus}
            disabled={savingBonus}
            className="rounded-lg bg-orange-600 px-4 py-2 text-sm font-medium text-white hover:bg-orange-500 disabled:opacity-50"
          >
            {savingBonus ? "Saving..." : "Save"}
          </button>
        </div>
      </section>
    <section className="admin-card rounded-2xl p-6 sm:p-8">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white/90">Users</h2>
          <p className="text-sm text-slate-400">
            {usersTab === "all" ? users.length : filteredUsers.length} {usersTab === "blocked" ? "blocked" : ""} users
          </p>
        </div>
        <div className="flex gap-2">
          {(["all", "blocked"] as const).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setUsersTab(t)}
              className={`rounded-full px-4 py-2 text-sm font-medium ${
                usersTab === t
                  ? "bg-orange-500/80 text-white"
                  : "bg-slate-700/50 text-slate-400 hover:bg-slate-600/50"
              }`}
            >
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
      </div>
      <ul className="space-y-2">
        {filteredUsers.map((u) => (
          <li
            key={u.id}
            role="button"
            tabIndex={0}
            onClick={() => setSelectedUser(u)}
            onKeyDown={(e) => e.key === "Enter" && setSelectedUser(u)}
            className="admin-list-item flex cursor-pointer items-center justify-between rounded-xl px-4 py-3.5 transition hover:border-orange-500/30"
          >
            <div className="min-w-0 flex-1">
              <div className="font-medium text-white">{u.displayName}</div>
              <div className="mt-0.5 truncate text-xs text-slate-500">{u.id}</div>
            </div>
            <span className="ml-3 shrink-0 rounded-lg bg-amber-500/20 px-3 py-1 font-medium text-amber-300">
              {u.coins} coins
            </span>
          </li>
        ))}
      </ul>
      {selectedUser && (
        <UserProfileModal
          user={selectedUser}
          canAddCoins={canAddCoins}
          onClose={() => setSelectedUser(null)}
          onUserUpdate={(u) => setSelectedUser(u)}
          onDelete={() => {
            onSuccess();
            setSelectedUser(null);
          }}
        />
      )}
    </section>
    </div>
  );
}

function UserProfileModal({
  user,
  canAddCoins,
  onClose,
  onUserUpdate,
  onDelete,
}: {
  user: User;
  canAddCoins: boolean;
  onClose: () => void;
  onUserUpdate: (user: User) => void;
  onDelete: () => void;
}) {
  const [amount, setAmount] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [blocking, setBlocking] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("click", close);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("click", close);
      document.removeEventListener("keydown", esc);
    };
  }, [onClose]);

  const handleAddCoins = async (e: React.FormEvent) => {
    e.preventDefault();
    const num = Number(amount);
    if (isNaN(num) || num <= 0) return;
    setSubmitting(true);
    try {
      const res = await fetch(`/api/admin/users/${user.id}/coins`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ amount: num }),
      });
      if (!res.ok) throw new Error(await res.text());
      const updated = await res.json();
      setAmount("");
      onUserUpdate(updated);
    } catch {
      alert("Failed to add coins");
    } finally {
      setSubmitting(false);
    }
  };

  const handleBlockUnblock = async () => {
    setBlocking(true);
    try {
      const endpoint = user.isBlocked ? "unblock" : "block";
      const res = await fetch(`/api/admin/users/${user.id}/${endpoint}`, { method: "POST" });
      if (!res.ok) throw new Error(await res.text());
      const updated = await res.json();
      onUserUpdate(updated);
    } catch {
      alert("Failed to update block status");
    } finally {
      setBlocking(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm("Are you sure you want to delete this user? This cannot be undone.")) return;
    setDeleting(true);
    try {
      const res = await fetch(`/api/admin/users/${user.id}`, { method: "DELETE" });
      if (!res.ok) throw new Error(await res.text());
      onDelete();
    } catch {
      alert("Failed to delete user");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="fixed inset-0 top-16 z-50 flex items-center justify-center bg-black/70 p-4">
      <div
        ref={ref}
        className="max-h-[calc(100vh-6rem)] w-full max-w-md overflow-y-auto rounded-2xl border border-slate-600/50 bg-slate-900 p-6 shadow-xl"
      >
        <div className="mb-6 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">User Profile</h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-2 text-slate-400 transition hover:bg-white/10 hover:text-white"
            aria-label="Close"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <dl className="space-y-4">
          <div>
            <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Display Name</dt>
            <dd className="mt-1 font-medium text-white">{user.displayName}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Email</dt>
            <dd className="mt-1 text-slate-200">{user.email}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">User ID</dt>
            <dd className="mt-1 font-mono text-sm text-slate-400">{user.id}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Coins</dt>
            <dd className="mt-1 font-medium text-amber-300">{user.coins}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Status</dt>
            <dd className="mt-1">
              <span className="rounded-lg px-2 py-0.5 text-xs font-medium text-slate-300">
                {user.isBlocked ? "Blocked" : "Active"}
              </span>
            </dd>
          </div>
        </dl>
        <div className="mt-8 space-y-4 border-t border-slate-700/50 pt-6">
          {canAddCoins && (
            <form onSubmit={handleAddCoins} className="flex gap-2">
              <input
                type="number"
                min="1"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="Amount"
                className="admin-input w-24 rounded-lg px-3 py-2 text-sm"
              />
              <button
                type="submit"
                disabled={submitting || !amount}
                className="admin-btn-primary rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50"
              >
                {submitting ? "Adding..." : "Add Coins"}
              </button>
            </form>
          )}
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={handleBlockUnblock}
              disabled={blocking}
              className={`rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 ${
                user.isBlocked
                  ? "bg-emerald-600 text-white hover:bg-emerald-500"
                  : "bg-amber-600/80 text-white hover:bg-amber-500/80"
              }`}
            >
              {blocking ? "..." : user.isBlocked ? "Unblock" : "Block"}
            </button>
            <button
              type="button"
              onClick={handleDelete}
              disabled={deleting}
              className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50"
            >
              {deleting ? "..." : "Delete Account"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

type DepositRequestWithUser = {
  id: string;
  userId: string;
  amount: number;
  utr: string;
  status: string;
  createdAt: string;
  user?: User;
};

type WithdrawalRequestWithUser = {
  id: string;
  userId: string;
  amount: number;
  upiId: string;
  status: string;
  rejectNote?: string;
  chargePercent?: number;
  createdAt: string;
  user?: User;
};

function CoinsSection({
  users,
  onSuccess,
}: {
  users: User[];
  onSuccess: () => void;
}) {
  const [coinsTab, setCoinsTab] = useState<"deposits" | "withdrawals">("deposits");
  const [depositRequests, setDepositRequests] = useState<DepositRequestWithUser[]>([]);
  const [withdrawalRequests, setWithdrawalRequests] = useState<WithdrawalRequestWithUser[]>([]);
  const [loadingDeposits, setLoadingDeposits] = useState(false);
  const [loadingWithdrawals, setLoadingWithdrawals] = useState(false);
  const [withdrawalCharge, setWithdrawalCharge] = useState(0);
  const [chargeInput, setChargeInput] = useState("");
  const [savingCharge, setSavingCharge] = useState(false);
  const [depositQrUrl, setDepositQrUrl] = useState<string | null>(null);
  const [qrFile, setQrFile] = useState<File | null>(null);
  const [qrPreview, setQrPreview] = useState<string | null>(null);
  const [savingQr, setSavingQr] = useState(false);

  const fetchDepositQr = useCallback(async () => {
    try {
      const res = await fetch("/api/admin/deposit-qr");
      if (res.ok) {
        const { url } = await res.json();
        setDepositQrUrl(url);
      }
    } catch {
      setDepositQrUrl(null);
    }
  }, []);

  const fetchDeposits = useCallback(async () => {
    setLoadingDeposits(true);
    try {
      const res = await fetch("/api/admin/deposits?status=pending");
      if (res.ok) setDepositRequests(await res.json());
    } catch {
      setDepositRequests([]);
    } finally {
      setLoadingDeposits(false);
    }
  }, []);

  const fetchWithdrawals = useCallback(async () => {
    setLoadingWithdrawals(true);
    try {
      const [wRes, cRes] = await Promise.all([
        fetch("/api/admin/withdrawals?status=pending"),
        fetch("/api/admin/withdrawal-charge"),
      ]);
      if (wRes.ok) setWithdrawalRequests(await wRes.json());
      if (cRes.ok) {
        const { chargePercent } = await cRes.json();
        setWithdrawalCharge(chargePercent);
        setChargeInput(String(chargePercent));
      }
    } catch {
      setWithdrawalRequests([]);
    } finally {
      setLoadingWithdrawals(false);
    }
  }, []);

  useEffect(() => {
    if (coinsTab === "deposits") {
      fetchDeposits();
      fetchDepositQr();
    } else {
      fetchWithdrawals();
    }
  }, [coinsTab, fetchDeposits, fetchDepositQr, fetchWithdrawals]);

  const handleSaveCharge = async () => {
    const p = Number(chargeInput);
    if (isNaN(p) || p < 0 || p > 100) {
      alert("Charge must be 0-100");
      return;
    }
    setSavingCharge(true);
    try {
      const res = await fetch("/api/admin/withdrawal-charge", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chargePercent: p }),
      });
      if (!res.ok) throw new Error(await res.text());
      const { chargePercent } = await res.json();
      setWithdrawalCharge(chargePercent);
      setChargeInput(String(chargePercent));
      onSuccess();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSavingCharge(false);
    }
  };

  const handleQrFileChange = (file: File) => {
    setQrFile(file);
    setQrPreview(URL.createObjectURL(file));
  };

  const handleQrClear = () => {
    setQrFile(null);
    if (qrPreview) URL.revokeObjectURL(qrPreview);
    setQrPreview(null);
  };

  const handleSaveQr = async () => {
    if (qrFile) {
      setSavingQr(true);
      try {
        const url = await uploadImage(qrFile);
        const res = await fetch("/api/admin/deposit-qr", {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        });
        if (!res.ok) throw new Error(await res.text());
        const { url: savedUrl } = await res.json();
        setDepositQrUrl(savedUrl);
        handleQrClear();
        onSuccess();
      } catch (err) {
        alert(err instanceof Error ? err.message : "Failed to upload QR");
      } finally {
        setSavingQr(false);
      }
    } else if (depositQrUrl) {
      if (!confirm("Remove the deposit QR code? Users will see a placeholder.")) return;
      setSavingQr(true);
      try {
        const res = await fetch("/api/admin/deposit-qr", {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: null }),
        });
        if (!res.ok) throw new Error(await res.text());
        setDepositQrUrl(null);
        onSuccess();
      } catch (err) {
        alert(err instanceof Error ? err.message : "Failed to remove QR");
      } finally {
        setSavingQr(false);
      }
    }
  };

  const handleDepositAction = async (id: string, action: "accept" | "reject" | "block") => {
    try {
      const res = await fetch(`/api/admin/deposits/${id}/${action}`, { method: "POST" });
      if (!res.ok) throw new Error(await res.text());
      fetchDeposits();
      onSuccess();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed");
    }
  };

  const handleWithdrawAccept = async (id: string) => {
    try {
      const res = await fetch(`/api/admin/withdrawals/${id}/accept`, { method: "POST" });
      if (!res.ok) throw new Error(await res.text());
      fetchWithdrawals();
      onSuccess();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed");
    }
  };

  const handleWithdrawReject = async (id: string) => {
    const note = prompt("Enter rejection reason (e.g. wrong UPI ID):");
    if (note === null) return;
    const trimmed = note.trim();
    if (!trimmed) {
      alert("Rejection note is required");
      return;
    }
    try {
      const res = await fetch(`/api/admin/withdrawals/${id}/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ note: trimmed }),
      });
      if (!res.ok) throw new Error(await res.text());
      fetchWithdrawals();
      onSuccess();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex gap-2">
        {(["deposits", "withdrawals"] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setCoinsTab(t)}
            className={`rounded-full px-4 py-2 text-sm font-medium ${
              coinsTab === t
                ? "bg-orange-500/80 text-white"
                : "bg-slate-700/50 text-slate-400 hover:bg-slate-600/50"
            }`}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {coinsTab === "deposits" && (
        <div className="space-y-6">
          <section className="admin-card rounded-2xl p-6 sm:p-8">
            <h3 className="mb-3 text-sm font-medium text-slate-300">Deposit QR Code</h3>
            <p className="mb-4 text-xs text-slate-400">
              Upload or update the QR code shown to users when they deposit. They scan this to pay.
            </p>
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
              <div className="flex flex-col gap-2">
                <label className="block text-xs text-slate-500">Current / New QR</label>
                <label className="admin-input flex min-h-[140px] cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-4 py-6 transition hover:border-orange-500/50">
                  <input
                    type="file"
                    accept="image/jpeg,image/png,image/gif,image/webp"
                    className="hidden"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) handleQrFileChange(f);
                    }}
                  />
                  {(qrPreview || depositQrUrl) ? (
                    <img
                      src={qrPreview ?? depositQrUrl ?? ""}
                      alt="QR"
                      className="mb-2 max-h-32 max-w-32 rounded-lg object-contain"
                    />
                  ) : (
                    <svg className="mb-2 h-12 w-12 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" />
                    </svg>
                  )}
                  <span className="text-sm text-slate-400">
                    {qrFile ? qrFile.name : "Click to upload or update"}
                  </span>
                </label>
                <div className="flex gap-2">
                  {qrFile && (
                    <button
                      type="button"
                      onClick={handleQrClear}
                      className="rounded-lg bg-slate-700/50 px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-600/50"
                    >
                      Clear
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={handleSaveQr}
                    disabled={savingQr || (!qrFile && !depositQrUrl)}
                    className="rounded-lg bg-orange-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-orange-500 disabled:opacity-50"
                  >
                    {savingQr ? "Saving..." : qrFile ? "Upload & Update" : depositQrUrl ? "Remove QR" : "Upload"}
                  </button>
                </div>
              </div>
            </div>
          </section>
          <section className="admin-card rounded-2xl p-6 sm:p-8">
            <div className="mb-3 flex items-center justify-between gap-2">
              <h3 className="text-sm font-medium text-slate-300">Pending Deposit Requests</h3>
              <button
                type="button"
                onClick={fetchDeposits}
                disabled={loadingDeposits}
                className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-700/50 text-slate-400 hover:bg-slate-600/50 hover:text-white disabled:opacity-50"
                title="Refresh list"
              >
                <svg className={`h-4 w-4 ${loadingDeposits ? "animate-spin" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </button>
            </div>
            {loadingDeposits ? (
              <div className="flex justify-center py-8">
                <div className="h-8 w-8 animate-spin rounded-full border-2 border-orange-500/30 border-t-orange-500" />
              </div>
            ) : depositRequests.length === 0 ? (
              <p className="py-6 text-center text-sm text-slate-400">No pending deposit requests</p>
            ) : (
              <ul className="space-y-3">
                {depositRequests.map((r) => (
                  <li
                    key={r.id}
                    className="flex flex-col gap-4 rounded-xl border border-slate-600/50 bg-slate-800/30 p-4"
                  >
                    <div className="min-w-0">
                      <p className="font-semibold text-white">{r.user?.displayName ?? "Unknown"}</p>
                      <p className="font-mono text-xs text-slate-400 break-all">{r.userId}</p>
                      <p className="mt-1 text-sm text-slate-300 break-all">UTR: {r.utr}</p>
                      <p className="text-sm font-medium text-amber-300">{r.amount} coins</p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => handleDepositAction(r.id, "accept")}
                        className="flex items-center justify-center rounded-lg bg-emerald-600 p-2.5 text-white hover:bg-emerald-500"
                        title="Accept"
                      >
                        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                        </svg>
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDepositAction(r.id, "reject")}
                        className="flex items-center justify-center rounded-lg bg-rose-600 p-2.5 text-white hover:bg-rose-500"
                        title="Reject"
                      >
                        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDepositAction(r.id, "block")}
                        className="flex items-center justify-center rounded-lg bg-slate-600 p-2.5 text-white hover:bg-slate-500"
                        title="Block user"
                      >
                        <span className="text-lg">🚫</span>
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <AddCoinsSection users={users} onSuccess={onSuccess} />
        </div>
      )}

      {coinsTab === "withdrawals" && (
        <>
        <section className="admin-card rounded-2xl p-6 sm:p-8">
          <h3 className="mb-3 text-sm font-medium text-slate-300">Withdrawal Charge</h3>
          <p className="mb-4 text-xs text-slate-400">
            Set the charge % deducted from withdrawals. New requests use this rate; existing requests keep their original rate.
          </p>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-4">
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="0"
                max="100"
                step="0.5"
                value={chargeInput}
                onChange={(e) => setChargeInput(e.target.value)}
                placeholder="0"
                className="admin-input w-24 rounded-lg px-3 py-2 text-sm text-white"
              />
              <span className="text-sm text-slate-400">%</span>
            </div>
            <button
              type="button"
              onClick={handleSaveCharge}
              disabled={savingCharge}
              className="rounded-lg bg-orange-600 px-4 py-2 text-sm font-medium text-white hover:bg-orange-500 disabled:opacity-50"
            >
              {savingCharge ? "Saving..." : "Save"}
            </button>
          </div>
        </section>
        <section className="admin-card rounded-2xl p-6 sm:p-8">
          <div className="mb-3 flex items-center justify-between gap-2">
            <h3 className="text-sm font-medium text-slate-300">Pending Withdrawal Requests</h3>
            <button
              type="button"
              onClick={fetchWithdrawals}
              disabled={loadingWithdrawals}
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-700/50 text-slate-400 hover:bg-slate-600/50 hover:text-white disabled:opacity-50"
              title="Refresh list"
            >
              <svg className={`h-4 w-4 ${loadingWithdrawals ? "animate-spin" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>
          </div>
          {loadingWithdrawals ? (
            <div className="flex justify-center py-8">
              <div className="h-8 w-8 animate-spin rounded-full border-2 border-orange-500/30 border-t-orange-500" />
            </div>
          ) : withdrawalRequests.length === 0 ? (
            <p className="py-6 text-center text-sm text-slate-400">No pending withdrawal requests</p>
          ) : (
            <ul className="space-y-3">
              {withdrawalRequests.map((r) => (
                <li
                  key={r.id}
                  className="flex flex-col gap-4 rounded-xl border border-slate-600/50 bg-slate-800/30 p-4"
                >
                  <div className="min-w-0">
                    <p className="font-semibold text-white">{r.user?.displayName ?? "Unknown"}</p>
                    <p className="font-mono text-xs text-slate-400 break-all">{r.userId}</p>
                    <p className="mt-1 text-sm text-slate-300 break-all">UPI: {r.upiId}</p>
                    <p className="text-sm font-medium text-amber-300">
                      Coins withdraw: {r.amount}
                    </p>
                    <p className="text-sm font-medium text-amber-300">
                      To pay: {Math.round(r.amount * (1 - (r.chargePercent ?? 0) / 100))}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => handleWithdrawAccept(r.id)}
                      className="flex items-center justify-center rounded-lg bg-emerald-600 p-2.5 text-white hover:bg-emerald-500"
                      title="Accept"
                    >
                      <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    </button>
                    <button
                      type="button"
                      onClick={() => handleWithdrawReject(r.id)}
                      className="flex items-center justify-center rounded-lg bg-rose-600 p-2.5 text-white hover:bg-rose-500"
                      title="Reject"
                    >
                      <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
        </>
      )}
    </div>
  );
}

function AddCoinsSection({
  users,
  onSuccess,
}: {
  users: User[];
  onSuccess: () => void;
}) {
  const [searchQuery, setSearchQuery] = useState("");
  const [amount, setAmount] = useState("");
  const [note, setNote] = useState("From admin");
  const [submitting, setSubmitting] = useState(false);

  const searchTrimmed = searchQuery.trim();
  const matchedUser = searchTrimmed
    ? users.find((u) => u.id.toLowerCase().includes(searchTrimmed.toLowerCase()))
    : null;
  const showNoUserFound = searchTrimmed.length > 0 && !matchedUser;
  const displayUser = matchedUser ?? null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!displayUser || !amount) return;
    const num = Number(amount);
    if (isNaN(num) || num <= 0) return;
    setSubmitting(true);
    try {
      const res = await fetch(`/api/admin/users/${displayUser.id}/coins`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ amount: num, description: note.trim() || "From admin" }),
      });
      if (!res.ok) throw new Error(await res.text());
      setAmount("");
      setNote("From admin");
      setSearchQuery("");
      onSuccess();
    } catch (err) {
      alert("Failed to add coins");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="admin-card rounded-2xl p-6 sm:p-8">
      <h2 className="mb-1 text-base font-semibold text-white/90">Add Coins</h2>
      <p className="mb-6 text-sm text-slate-400">Search by user ID, then add coins to their account</p>
      <form onSubmit={handleSubmit} className="space-y-5">
        <div>
          <label className="mb-2 block text-sm font-medium text-slate-300">Search by User ID</label>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
            placeholder="Type user ID..."
          />
        </div>

        {showNoUserFound && (
          <p className="rounded-lg bg-rose-500/20 px-4 py-3 text-sm font-medium text-rose-300">
            No user found
          </p>
        )}

        {displayUser && !showNoUserFound && (
          <div className="space-y-4">
            <div className="rounded-xl border border-slate-600/50 bg-slate-800/30 p-4">
              <p className="mb-1 text-xs font-medium uppercase tracking-wider text-slate-500">
                User found — confirm before adding coins
              </p>
              <p className="font-mono text-sm text-slate-400">{displayUser.id}</p>
              <p className="font-semibold text-white">{displayUser.displayName}</p>
              <p className="text-sm text-slate-400">{displayUser.email}</p>
              <p className="mt-1 text-sm font-medium text-amber-300">{displayUser.coins} coins</p>
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">Amount to Add</label>
              <input
                type="number"
                min="1"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                required
                className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
                placeholder="e.g. 100"
              />
            </div>
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">Note</label>
              <input
                type="text"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                className="admin-input w-full rounded-xl px-4 py-3 text-white outline-none"
                placeholder="e.g. From admin, Refund, Winnings, Match entry..."
              />
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="admin-btn-primary rounded-xl px-6 py-3 font-medium text-white disabled:opacity-50"
            >
              {submitting ? "Adding..." : "Add Coins"}
            </button>
          </div>
        )}
      </form>
    </section>
  );
}
