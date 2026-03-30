/**
 * In-memory admin store for demo.
 * Replace with Supabase calls for production.
 */

import bcrypt from "bcryptjs";

export type Game = { id: string; name: string; imageUrl: string | null };
export type GameMode = { id: string; gameId: string; name: string; imageUrl: string | null };
export type MatchType = "solo" | "duo" | "squad";

export type RankReward = { fromRank: number; toRank: number; coins: number };

export type PrizePool = {
  coinsPerKill: number;
  totalPrizePool?: number; // Total prize pool for the whole match (displayed with coins per kill)
  rankRewards: RankReward[];
};

export type Match = {
  id: string;
  gameModeId: string;
  title: string;
  entryFee: number;
  roomCode: string | null;
  roomPassword: string | null;
  status: "upcoming" | "ongoing" | "ended" | "completed" | "cancelled";
  maxParticipants: number;
  scheduledAt: string;
  registrationLocked: boolean;
  matchType: MatchType;
  prizePool: PrizePool;
};

export type TeamMember = { inGameName: string; inGameUid: string; kills?: number };
export type MatchParticipant = {
  id: string;
  matchId: string;
  userId: string;
  teamMembers: TeamMember[];
  joinedAt: string;
  rank?: number; // Set when player dies; used for live leaderboard order
};
export type User = { id: string; email: string; displayName: string; coins: number; isBlocked?: boolean };

export type CoinTransaction = {
  id: string;
  userId: string;
  amount: number;
  type: "admin_add" | "match_entry" | "refund" | "deposit" | "deposit_failed" | "withdraw" | "withdraw_failed" | "signup_bonus" | "match_winning";
  referenceId?: string;
  description?: string;
  createdAt: string;
};

export type DepositRequest = {
  id: string;
  userId: string;
  amount: number;
  utr: string;
  status: "pending" | "accepted" | "rejected";
  createdAt: string;
};

export type WithdrawalRequest = {
  id: string;
  userId: string;
  amount: number;
  upiId: string;
  status: "pending" | "accepted" | "rejected";
  rejectNote?: string;
  chargePercent?: number; // charge % at time of request (0 = no charge)
  createdAt: string;
};

export type AdminPermission = {
  id: string;
  adminname: string;
  passwordHash: string;
  isMasterAdmin: boolean;
  usersAccess: boolean;
  coinsAccess: boolean;
  gamesAccessType: "all" | "specific";
  allowedGameIds: string[];
  createdAt: string;
};

let gameIdCounter = 1;
let modeIdCounter = 1;
let matchIdCounter = 1;

const games: Game[] = [];
const gameModes: GameMode[] = [];

const defaultPrizePool: PrizePool = {
  coinsPerKill: 5,
  totalPrizePool: 0,
  rankRewards: [{ fromRank: 1, toRank: 5, coins: 30 }, { fromRank: 6, toRank: 10, coins: 20 }],
};

const matches: Match[] = [];

// Display order for ongoing matches: when admin sets rank, we swap positions
const matchParticipantOrder: Record<string, string[]> = {};

// Persist admin data across Next.js hot reloads in development (for testing server)
const globalForAdmin = globalThis as unknown as {
  adminPermissions?: AdminPermission[];
  adminIdCounter?: number;
  withdrawalChargePercent?: number;
  signupBonus?: number;
  customerSupportUrl?: string | null;
  adminStoreUsers?: User[];
  adminStoreCoinTransactions?: CoinTransaction[];
  adminStoreDepositRequests?: DepositRequest[];
  adminStoreWithdrawalRequests?: WithdrawalRequest[];
  adminStoreMatchParticipants?: MatchParticipant[];
  adminStoreMatchParticipantIdCounter?: number;
  adminStoreTransactionIdCounter?: number;
  adminStoreDepositRequestIdCounter?: number;
  adminStoreWithdrawalRequestIdCounter?: number;
};

const matchParticipants: MatchParticipant[] = globalForAdmin.adminStoreMatchParticipants ?? (globalForAdmin.adminStoreMatchParticipants = []);
let matchParticipantIdCounter = globalForAdmin.adminStoreMatchParticipantIdCounter ?? 1;

function generateUniqueUserId(): string {
  const existing = new Set(users.map((u) => u.id));
  let id: string;
  do {
    id = String(Math.floor(10000 + Math.random() * 90000));
  } while (existing.has(id));
  return id;
}

const users: User[] = globalForAdmin.adminStoreUsers ?? (globalForAdmin.adminStoreUsers = []);
const coinTransactions: CoinTransaction[] = globalForAdmin.adminStoreCoinTransactions ?? (globalForAdmin.adminStoreCoinTransactions = []);
const depositRequests: DepositRequest[] = globalForAdmin.adminStoreDepositRequests ?? (globalForAdmin.adminStoreDepositRequests = []);
const withdrawalRequests: WithdrawalRequest[] = globalForAdmin.adminStoreWithdrawalRequests ?? (globalForAdmin.adminStoreWithdrawalRequests = []);

function nextTxId() {
  const v = (globalForAdmin.adminStoreTransactionIdCounter ?? 1);
  globalForAdmin.adminStoreTransactionIdCounter = v + 1;
  return `tx-${v}`;
}
function nextDrId() {
  const v = (globalForAdmin.adminStoreDepositRequestIdCounter ?? 1);
  globalForAdmin.adminStoreDepositRequestIdCounter = v + 1;
  return `dr-${v}`;
}
function nextWrId() {
  const v = (globalForAdmin.adminStoreWithdrawalRequestIdCounter ?? 1);
  globalForAdmin.adminStoreWithdrawalRequestIdCounter = v + 1;
  return `wr-${v}`;
}

let depositQrUrl: string | null = null;
let customerSupportUrl: string | null = globalForAdmin.customerSupportUrl ?? null;

const initialAdminPermissions: AdminPermission[] = [
  {
    id: "admin-master",
    adminname: "masteradmin",
    passwordHash: bcrypt.hashSync("master123", 10),
    isMasterAdmin: true,
    usersAccess: true,
    coinsAccess: true,
    gamesAccessType: "all",
    allowedGameIds: [],
    createdAt: new Date().toISOString(),
  },
];

const adminPermissions =
  globalForAdmin.adminPermissions ?? (globalForAdmin.adminPermissions = [...initialAdminPermissions]);
let adminIdCounter = globalForAdmin.adminIdCounter ?? 1;
let withdrawalChargePercent = globalForAdmin.withdrawalChargePercent ?? 0;
let signupBonus = globalForAdmin.signupBonus ?? 0;

function getGamesForAdmin(admin: AdminPermission): Game[] {
  if (admin.isMasterAdmin || admin.gamesAccessType === "all") return [...games];
  return games.filter((g) => admin.allowedGameIds.includes(g.id));
}

export const adminStore = {
  games: (adminId?: string) => {
    if (!adminId) return [...games];
    const admin = adminPermissions.find((a) => a.id === adminId);
    if (!admin) return [...games];
    return getGamesForAdmin(admin);
  },
  addGame: (name: string, imageUrl: string | null) => {
    const id = String(gameIdCounter++);
    games.push({ id, name, imageUrl });
    return games[games.length - 1];
  },
  deleteGame: (id: string) => {
    const i = games.findIndex((g) => g.id === id);
    if (i === -1) return false;
    games.splice(i, 1);
    return true;
  },
  renameGame: (id: string, name: string) => {
    const g = games.find((x) => x.id === id);
    if (!g) return null;
    g.name = name;
    return g;
  },

  gameModes: (gameId?: string) =>
    gameId ? gameModes.filter((m) => m.gameId === gameId) : [...gameModes],
  addGameMode: (gameId: string, name: string, imageUrl: string | null) => {
    const id = `m${modeIdCounter++}`;
    gameModes.push({ id, gameId, name, imageUrl });
    return gameModes[gameModes.length - 1];
  },
  deleteMode: (id: string) => {
    const i = gameModes.findIndex((m) => m.id === id);
    if (i === -1) return false;
    gameModes.splice(i, 1);
    return true;
  },
  renameMode: (id: string, name: string) => {
    const m = gameModes.find((x) => x.id === id);
    if (!m) return null;
    m.name = name;
    return m;
  },

  matches: (modeId?: string) =>
    modeId ? matches.filter((m) => m.gameModeId === modeId) : [...matches],
  addMatch: (
    gameModeId: string,
    title: string,
    entryFee: number,
    maxParticipants: number,
    scheduledAt: string,
    matchType: MatchType = "solo",
    prizePool: PrizePool = defaultPrizePool
  ) => {
    const id = `match${matchIdCounter++}`;
    matches.push({
      id,
      gameModeId,
      title,
      entryFee,
      roomCode: null,
      roomPassword: null,
      status: "upcoming",
      maxParticipants,
      scheduledAt,
      registrationLocked: false,
      matchType,
      prizePool,
    });
    return matches[matches.length - 1];
  },
  updateMatchRoomInfo: (matchId: string, roomCode: string, roomPassword: string) => {
    const m = matches.find((x) => x.id === matchId);
    if (!m || m.status !== "upcoming") return null;
    m.roomCode = roomCode;
    m.roomPassword = roomPassword;
    return m;
  },
  startMatch: (matchId: string, roomCode?: string, roomPassword?: string) => {
    const m = matches.find((x) => x.id === matchId);
    if (!m || m.status !== "upcoming") return null;
    m.roomCode = roomCode ?? m.roomCode;
    m.roomPassword = roomPassword ?? m.roomPassword;
    if (!m.roomCode || !m.roomPassword) return null;
    m.status = "ongoing";
    m.registrationLocked = true;
    return m;
  },
  cancelMatch: (matchId: string) => {
    const m = matches.find((x) => x.id === matchId);
    if (!m || m.status !== "upcoming") return null;
    m.status = "cancelled";
    const participants = matchParticipants.filter((p) => p.matchId === matchId);
    for (const p of participants) {
      const u = users.find((x) => x.id === p.userId);
      if (u) {
        u.coins += m.entryFee;
        coinTransactions.push({
          id: nextTxId(),
          userId: p.userId,
          amount: m.entryFee,
          type: "refund",
          referenceId: matchId,
          description: `Refund: ${m.title} cancelled`,
          createdAt: new Date().toISOString(),
        });
      }
    }
    return m;
  },
  finishMatch: (matchId: string) => {
    const m = matches.find((x) => x.id === matchId);
    if (!m || m.status !== "ongoing") return null;
    const participants = matchParticipants
      .filter((p) => p.matchId === matchId);
    const withRank = participants
      .filter((p) => typeof p.rank === "number" && p.rank >= 1)
      .sort((a, b) => (a.rank ?? 0) - (b.rank ?? 0));
    const rewards = m.prizePool?.rankRewards ?? [];
    const cpk = m.prizePool?.coinsPerKill ?? 0;
    for (const p of withRank) {
      const totalKills = (p.teamMembers ?? []).reduce((s, t) => s + (t.kills ?? 0), 0);
      let coins = totalKills * cpk;
      for (const r of rewards) {
        if (p.rank! >= r.fromRank && p.rank! <= r.toRank) {
          coins += r.coins;
          break;
        }
      }
      if (coins > 0) {
        const u = users.find((x) => x.id === p.userId);
        if (u) {
          u.coins += coins;
          coinTransactions.push({
            id: nextTxId(),
            userId: p.userId,
            amount: coins,
            type: "match_winning",
            referenceId: matchId,
            description: `Winning with match ${matchId}`,
            createdAt: new Date().toISOString(),
          });
        }
      }
    }
    m.status = "completed";
    return m;
  },
  deleteMatch: (id: string) => {
    const i = matches.findIndex((m) => m.id === id);
    if (i === -1) return false;
    matches.splice(i, 1);
    return true;
  },
  renameMatch: (id: string, title: string) => {
    const m = matches.find((x) => x.id === id);
    if (!m) return null;
    m.title = title;
    return m;
  },

  users: () => [...users],
  getSignupBonus: () => signupBonus,
  setSignupBonus: (amount: number) => {
    const a = Math.max(0, amount);
    signupBonus = a;
    globalForAdmin.signupBonus = a;
    return a;
  },
  addUser: (email: string, displayName: string, password: string) => {
    const existing = users.find((u) => u.email?.toLowerCase() === email.toLowerCase());
    if (existing) return null;
    if (!password || password.length < 6) return null;
    const id = generateUniqueUserId();
    const bonus = signupBonus;
    const passwordHash = bcrypt.hashSync(password, 10);
    const user: User & { passwordHash?: string } = {
      id,
      email,
      displayName,
      coins: bonus,
      isBlocked: false,
      passwordHash,
    };
    users.push(user);
    if (bonus > 0) {
      coinTransactions.push({
        id: nextTxId(),
        userId: id,
        amount: bonus,
        type: "signup_bonus",
        description: "Signup bonus",
        createdAt: new Date().toISOString(),
      });
    }
    return user;
  },
  signInUser: (email: string, password: string) => {
    const u = users.find((x) => x.email?.toLowerCase() === email.toLowerCase());
    if (!u || u.isBlocked) return null;
    const hash = (u as User & { passwordHash?: string }).passwordHash;
    if (!hash || !bcrypt.compareSync(password, hash)) return null;
    const { passwordHash: _, ...user } = u as User & { passwordHash?: string };
    return user;
  },
  addCoins: (userId: string, amount: number, description?: string) => {
    const u = users.find((x) => x.id === userId);
    if (!u) return null;
    u.coins += amount;
    coinTransactions.push({
      id: nextTxId(),
      userId,
      amount,
      type: "admin_add",
      description: description ?? "Admin added coins",
      createdAt: new Date().toISOString(),
    });
    return u;
  },
  addDepositRequest: (userId: string, amount: number, utr: string) => {
    const trimmed = utr.trim();
    if (depositRequests.some((r) => r.utr === trimmed)) return null;
    const id = nextDrId();
    const req: DepositRequest = {
      id,
      userId,
      amount,
      utr: trimmed,
      status: "pending",
      createdAt: new Date().toISOString(),
    };
    depositRequests.push(req);
    return req;
  },
  getDepositRequests: (status?: "pending" | "accepted" | "rejected") => {
    if (status) return depositRequests.filter((r) => r.status === status);
    return [...depositRequests];
  },
  getDepositRequest: (id: string) => depositRequests.find((r) => r.id === id),
  getDepositRequestsByUser: (userId: string) =>
    depositRequests.filter((r) => r.userId === userId).sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()),
  acceptDepositRequest: (id: string) => {
    const req = depositRequests.find((r) => r.id === id);
    if (!req || req.status !== "pending") return null;
    req.status = "accepted";
    const u = users.find((x) => x.id === req.userId);
    if (u) {
      u.coins += req.amount;
      coinTransactions.push({
        id: nextTxId(),
        userId: req.userId,
        amount: req.amount,
        type: "deposit",
        description: "Deposited",
        referenceId: req.utr,
        createdAt: new Date().toISOString(),
      });
    }
    return req;
  },
  rejectDepositRequest: (id: string) => {
    const req = depositRequests.find((r) => r.id === id);
    if (!req || req.status !== "pending") return null;
    req.status = "rejected";
    coinTransactions.push({
      id: nextTxId(),
      userId: req.userId,
      amount: req.amount,
      type: "deposit_failed",
      description: "Deposit rejected",
      referenceId: req.utr,
      createdAt: new Date().toISOString(),
    });
    return req;
  },
  blockDepositRequest: (id: string) => {
    const req = depositRequests.find((r) => r.id === id);
    if (!req || req.status !== "pending") return null;
    req.status = "rejected";
    const u = users.find((x) => x.id === req.userId);
    if (u) u.isBlocked = true;
    coinTransactions.push({
      id: nextTxId(),
      userId: req.userId,
      amount: req.amount,
      type: "deposit_failed",
      description: "Deposit rejected (user blocked)",
      referenceId: req.utr,
      createdAt: new Date().toISOString(),
    });
    return req;
  },
  getWithdrawalCharge: () => withdrawalChargePercent,
  setWithdrawalCharge: (percent: number) => {
    const p = Math.max(0, Math.min(100, percent));
    withdrawalChargePercent = p;
    globalForAdmin.withdrawalChargePercent = p;
    return p;
  },
  addWithdrawalRequest: (userId: string, amount: number, upiId: string) => {
    const u = users.find((x) => x.id === userId);
    if (!u || u.coins < amount) return null;
    u.coins -= amount;
    const id = nextWrId();
    const req: WithdrawalRequest = {
      id,
      userId,
      amount,
      upiId,
      status: "pending",
      chargePercent: withdrawalChargePercent,
      createdAt: new Date().toISOString(),
    };
    withdrawalRequests.push(req);
    return req;
  },
  getWithdrawalRequests: (status?: "pending" | "accepted" | "rejected") => {
    if (status) return withdrawalRequests.filter((r) => r.status === status);
    return [...withdrawalRequests];
  },
  getWithdrawalRequestsByUser: (userId: string) =>
    withdrawalRequests.filter((r) => r.userId === userId),
  getWithdrawalRequest: (id: string) => withdrawalRequests.find((r) => r.id === id),
  acceptWithdrawalRequest: (id: string) => {
    const req = withdrawalRequests.find((r) => r.id === id);
    if (!req || req.status !== "pending") return null;
    req.status = "accepted";
    coinTransactions.push({
      id: nextTxId(),
      userId: req.userId,
      amount: -req.amount,
      type: "withdraw",
      description: "Withdraw",
      referenceId: req.upiId,
      createdAt: new Date().toISOString(),
    });
    return req;
  },
  rejectWithdrawalRequest: (id: string, note: string) => {
    const req = withdrawalRequests.find((r) => r.id === id);
    if (!req || req.status !== "pending") return null;
    req.status = "rejected";
    req.rejectNote = note;
    const u = users.find((x) => x.id === req.userId);
    if (u) u.coins += req.amount;
    coinTransactions.push({
      id: nextTxId(),
      userId: req.userId,
      amount: req.amount,
      type: "refund",
      description: note?.trim() ? `Withdrawal rejected: ${note.trim()}` : "Withdrawal rejected - refunded",
      referenceId: req.upiId,
      createdAt: new Date().toISOString(),
    });
    return req;
  },
  transactions: (userId?: string) => {
    const list = userId
      ? coinTransactions.filter((t) => t.userId === userId)
      : [...coinTransactions];
    return list.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  },
  blockUser: (userId: string) => {
    const u = users.find((x) => x.id === userId);
    if (!u) return false;
    u.isBlocked = true;
    return true;
  },
  unblockUser: (userId: string) => {
    const u = users.find((x) => x.id === userId);
    if (!u) return false;
    u.isBlocked = false;
    return true;
  },
  deleteUser: (userId: string) => {
    const i = users.findIndex((x) => x.id === userId);
    if (i === -1) return false;
    users.splice(i, 1);
    return true;
  },

  getGame: (id: string) => games.find((g) => g.id === id),
  getMode: (id: string) => gameModes.find((m) => m.id === id),
  getMatch: (id: string) => matches.find((m) => m.id === id),
  getUser: (id: string) => users.find((u) => u.id === id),
  getParticipantsForMatch: (matchId: string) => {
    const list = matchParticipants.filter((p) => p.matchId === matchId);
    const order = matchParticipantOrder[matchId];
    if (order && order.length === list.length) {
      const byId = new Map(list.map((p) => [p.id, p]));
      return order.map((id) => byId.get(id)).filter(Boolean) as MatchParticipant[];
    }
    return list.sort((a, b) => new Date(a.joinedAt).getTime() - new Date(b.joinedAt).getTime());
  },
  updateParticipantKills: (matchId: string, participantId: string, kills: number[]) => {
    const p = matchParticipants.find((x) => x.matchId === matchId && x.id === participantId);
    if (!p) return null;
    p.teamMembers.forEach((tm, i) => {
      tm.kills = kills[i] ?? tm.kills ?? 0;
    });
    return p;
  },
  updateParticipantRank: (matchId: string, participantId: string, rank: number) => {
    const list = matchParticipants.filter((p) => p.matchId === matchId);
    const p = list.find((x) => x.id === participantId);
    if (!p || rank < 1 || rank > list.length) return null;
    let order = matchParticipantOrder[matchId];
    if (!order || order.length !== list.length) {
      order = list.sort((a, b) => new Date(a.joinedAt).getTime() - new Date(b.joinedAt).getTime()).map((x) => x.id);
      matchParticipantOrder[matchId] = order;
    }
    const idx = order.indexOf(participantId);
    if (idx === -1) return null;
    const rankIdx = rank - 1;
    p.rank = rank;
    [order[idx], order[rankIdx]] = [order[rankIdx], order[idx]];
    return p;
  },
  addMatchParticipant: (matchId: string, userId: string, teamMembers: { inGameName: string; inGameUid: string }[]) => {
    const id = `mp${matchParticipantIdCounter++}`;
    globalForAdmin.adminStoreMatchParticipantIdCounter = matchParticipantIdCounter;
    const p: MatchParticipant = {
      id,
      matchId,
      userId,
      teamMembers: teamMembers.map((tm) => ({ ...tm, kills: 0 })),
      joinedAt: new Date().toISOString(),
    };
    matchParticipants.push(p);
    return p;
  },

  joinMatch: (
    matchId: string,
    appUserId: string,
    inGameName: string,
    inGameUid: string,
    teamMembers?: { inGameName: string; inGameUid: string }[]
  ): { error?: string } | null => {
    const m = matches.find((x) => x.id === matchId);
    if (!m) return { error: "Match not found" };
    if (m.status !== "upcoming") return { error: "Registration closed" };
    if (m.registrationLocked) return { error: "Registration locked" };
    const u = users.find((x) => x.id === appUserId);
    if (!u) return { error: "User not found" };
    if (u.isBlocked) return { error: "Account is blocked" };
    if (u.coins < m.entryFee) return { error: "Insufficient coins" };
    const existing = matchParticipants.find((p) => p.matchId === matchId && p.userId === appUserId);
    if (existing) return { error: "Already registered" };
    const participants = matchParticipants.filter((p) => p.matchId === matchId);
    if (participants.length >= m.maxParticipants) return { error: "Match is full" };
    const members = [{ inGameName, inGameUid }, ...(teamMembers ?? [])].slice(0, 4);
    const newId = matchParticipantIdCounter++;
    globalForAdmin.adminStoreMatchParticipantIdCounter = matchParticipantIdCounter;
    matchParticipants.push({
      id: `mp${newId}`,
      matchId,
      userId: appUserId,
      teamMembers: members.map((tm) => ({ ...tm, kills: 0 })),
      joinedAt: new Date().toISOString(),
    });
    if (m.entryFee > 0) {
      u.coins -= m.entryFee;
      coinTransactions.push({
        id: nextTxId(),
        userId: appUserId,
        amount: -m.entryFee,
        type: "match_entry",
        referenceId: matchId,
        description: "Match entry fee",
        createdAt: new Date().toISOString(),
      });
    }
    return null;
  },

  getDepositQrUrl: () => depositQrUrl,
  setDepositQrUrl: (url: string | null) => {
    depositQrUrl = url;
    return depositQrUrl;
  },
  getCustomerSupportUrl: () => customerSupportUrl,
  setCustomerSupportUrl: (url: string | null) => {
    customerSupportUrl = url;
    globalForAdmin.customerSupportUrl = url;
    return customerSupportUrl;
  },

  // Admin auth & permissions
  login: async (adminname: string, password: string): Promise<AdminPermission | null> => {
    const admin = adminPermissions.find((a) => a.adminname.toLowerCase() === adminname.toLowerCase());
    if (!admin) return null;
    const ok = await bcrypt.compare(password, admin.passwordHash);
    return ok ? admin : null;
  },
  getAdminById: (id: string) => adminPermissions.find((a) => a.id === id) ?? null,
  getAllAdmins: () => adminPermissions.map((a) => ({ ...a, passwordHash: "[hidden]" })),
  createAdmin: (
    adminname: string,
    password: string,
    opts: {
      usersAccess: boolean;
      coinsAccess: boolean;
      gamesAccessType: "all" | "specific";
      allowedGameIds: string[];
    }
  ): AdminPermission | null => {
    if (adminPermissions.some((a) => a.adminname.toLowerCase() === adminname.toLowerCase())) return null;
    const id = `admin-${adminIdCounter++}`;
    globalForAdmin.adminIdCounter = adminIdCounter;
    const admin: AdminPermission = {
      id,
      adminname,
      passwordHash: bcrypt.hashSync(password, 10),
      isMasterAdmin: false,
      usersAccess: opts.usersAccess,
      coinsAccess: opts.coinsAccess,
      gamesAccessType: opts.gamesAccessType,
      allowedGameIds: opts.allowedGameIds ?? [],
      createdAt: new Date().toISOString(),
    };
    adminPermissions.push(admin);
    return admin;
  },
  deleteAdmin: (adminId: string): boolean => {
    const admin = adminPermissions.find((a) => a.id === adminId);
    if (!admin || admin.isMasterAdmin) return false;
    const i = adminPermissions.findIndex((a) => a.id === adminId);
    if (i === -1) return false;
    adminPermissions.splice(i, 1);
    return true;
  },
  updateAdminPassword: (adminId: string, newPassword: string): boolean => {
    const admin = adminPermissions.find((a) => a.id === adminId);
    if (!admin) return false;
    admin.passwordHash = bcrypt.hashSync(newPassword, 10);
    return true;
  },
  canAccessGames: (adminId: string) => {
    const admin = adminStore.getAdminById(adminId);
    return admin ? (admin.isMasterAdmin || admin.gamesAccessType === "all" || admin.allowedGameIds.length > 0) : false;
  },
  canAccessUsers: (adminId: string) => adminStore.getAdminById(adminId)?.usersAccess ?? false,
  canAccessCoins: (adminId: string) => adminStore.getAdminById(adminId)?.coinsAccess ?? false,
  isMasterAdmin: (adminId: string) => adminStore.getAdminById(adminId)?.isMasterAdmin ?? false,
};
