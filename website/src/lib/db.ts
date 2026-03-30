/**
 * Supabase database layer for app_users, deposits, withdrawals, transactions, admins, settings.
 * Use when NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are set.
 */

import bcrypt from "bcryptjs";
import { getSupabase } from "./supabase";

// Types matching admin-store
export type DbUser = { id: string; email: string; displayName: string; coins: number; isBlocked?: boolean };
export type DbDepositRequest = { id: string; userId: string; amount: number; utr: string; status: string; createdAt: string };
export type DbWithdrawalRequest = {
  id: string;
  userId: string;
  amount: number;
  upiId: string;
  status: string;
  rejectNote?: string;
  chargePercent?: number;
  createdAt: string;
};
export type DbCoinTransaction = {
  id: string;
  userId: string;
  amount: number;
  type: string;
  referenceId?: string;
  referenceText?: string;
  description?: string;
  createdAt: string;
};
export type DbAdmin = {
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

export type DbMatch = {
  id: string;
  gameModeId: string;
  title: string;
  entryFee: number;
  roomCode: string | null;
  roomPassword: string | null;
  status: string;
  maxParticipants: number;
  scheduledAt: string;
  registrationLocked: boolean;
  matchType: string;
  prizePool: { coinsPerKill: number; totalPrizePool?: number; rankRewards: { fromRank: number; toRank: number; coins: number }[] };
};

function toMatch(row: {
  id: string;
  game_mode_id: string;
  title: string;
  entry_fee: number;
  room_code?: string | null;
  room_password?: string | null;
  status: string;
  max_participants: number;
  starts_at?: string | null;
  registration_locked?: boolean;
  match_type?: string;
  coins_per_kill?: number;
  total_prize_pool?: number;
  rank_rewards?: unknown;
}): DbMatch {
  const rewards = Array.isArray(row.rank_rewards)
    ? (row.rank_rewards as { fromRank?: number; toRank?: number; coins?: number }[])
        .filter((r) => r && typeof r.fromRank === "number" && typeof r.toRank === "number" && typeof r.coins === "number")
        .map((r) => ({ fromRank: r.fromRank!, toRank: r.toRank!, coins: r.coins! }))
    : [];
  return {
    id: row.id,
    gameModeId: row.game_mode_id,
    title: row.title,
    entryFee: row.entry_fee ?? 0,
    roomCode: row.room_code ?? null,
    roomPassword: row.room_password ?? null,
    status: row.status ?? "upcoming",
    maxParticipants: row.max_participants ?? 100,
    scheduledAt: row.starts_at ?? "",
    registrationLocked: row.registration_locked ?? false,
    matchType: row.match_type ?? "solo",
    prizePool: {
      coinsPerKill: row.coins_per_kill ?? 5,
      totalPrizePool: row.total_prize_pool ?? 0,
      rankRewards: rewards,
    },
  };
}

function toUser(row: { id: string; email: string; display_name: string; coins: number; is_blocked?: boolean }): DbUser {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    coins: row.coins ?? 0,
    isBlocked: row.is_blocked ?? false,
  };
}

function toDepositRequest(row: { id: string; user_id: string; amount: number; utr: string; status: string; created_at: string }): DbDepositRequest {
  return {
    id: row.id,
    userId: row.user_id,
    amount: row.amount,
    utr: row.utr,
    status: row.status,
    createdAt: row.created_at,
  };
}

function toWithdrawalRequest(row: {
  id: string;
  user_id: string;
  amount: number;
  upi_id: string;
  status: string;
  reject_note?: string;
  charge_percent?: number;
  created_at: string;
}): DbWithdrawalRequest {
  return {
    id: row.id,
    userId: row.user_id,
    amount: row.amount,
    upiId: row.upi_id,
    status: row.status,
    rejectNote: row.reject_note,
    chargePercent: row.charge_percent != null ? Number(row.charge_percent) : undefined,
    createdAt: row.created_at,
  };
}

function toTransaction(row: {
  id: string;
  user_id: string;
  amount: number;
  type: string;
  reference_id?: string;
  reference_text?: string;
  description?: string;
  created_at: string;
}): DbCoinTransaction {
  return {
    id: row.id,
    userId: row.user_id,
    amount: row.amount,
    type: row.type,
    referenceId: row.reference_id,
    referenceText: row.reference_text,
    description: row.description,
    createdAt: row.created_at,
  };
}

export const db = {
  async users(): Promise<DbUser[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const { data, error } = await supabase.from("app_users").select("*").order("created_at", { ascending: false });
    if (error) return [];
    return (data ?? []).map(toUser);
  },

  async addUser(email: string, displayName: string, password: string): Promise<DbUser | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    if (!password || password.length < 6) return null;
    const { data: existing } = await supabase.from("app_users").select("id").ilike("email", email).single();
    if (existing) return null;

    const { data: bonusRow } = await supabase.from("app_settings").select("value").eq("key", "signup_bonus").single();
    const bonus = bonusRow?.value ? parseInt(bonusRow.value, 10) : 0;

    let id: string;
    const { data: idFromRpc } = await supabase.rpc("generate_app_user_id");
    if (typeof idFromRpc === "string") {
      id = idFromRpc;
    } else {
      id = String(Math.floor(10000 + Math.random() * 90000));
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const { data: user, error } = await supabase
      .from("app_users")
      .insert({ id, email, display_name: displayName, coins: Math.max(0, bonus), password_hash: passwordHash })
      .select()
      .single();
    if (error) return null;

    if (bonus > 0) {
      await supabase.from("app_coin_transactions").insert({
        user_id: id,
        amount: bonus,
        type: "signup_bonus",
        description: "Signup bonus",
      });
    }
    return toUser(user);
  },

  async signInUser(email: string, password: string): Promise<DbUser | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data } = await supabase.from("app_users").select("*").ilike("email", email).single();
    if (!data) return null;
    const u = data as { password_hash?: string | null; is_blocked?: boolean };
    if (u.is_blocked) return null;
    const hash = u.password_hash;
    if (!hash) return null;
    const ok = await bcrypt.compare(password, hash);
    if (!ok) return null;
    return toUser(data);
  },

  async getUser(id: string): Promise<DbUser | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data } = await supabase.from("app_users").select("*").eq("id", id).single();
    return data ? toUser(data) : null;
  },

  async addCoins(userId: string, amount: number, description?: string): Promise<DbUser | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: user } = await supabase.from("app_users").select("*").eq("id", userId).single();
    if (!user) return null;
    await supabase.from("app_users").update({ coins: user.coins + amount }).eq("id", userId);
    await supabase.from("app_coin_transactions").insert({
      user_id: userId,
      amount,
      type: "admin_add",
      description: description ?? "Admin added coins",
    });
    return db.getUser(userId);
  },

  async addMatchWinnings(userId: string, amount: number, matchId: string): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    const { data: user } = await supabase.from("app_users").select("*").eq("id", userId).single();
    if (!user) return false;
    await supabase.from("app_users").update({ coins: user.coins + amount }).eq("id", userId);
    await supabase.from("app_coin_transactions").insert({
      user_id: userId,
      amount,
      type: "match_winning",
      reference_id: matchId,
      description: `Winning with match ${matchId}`,
    });
    return true;
  },

  async blockUser(userId: string): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    const { error } = await supabase.from("app_users").update({ is_blocked: true }).eq("id", userId);
    return !error;
  },

  async unblockUser(userId: string): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    const { error } = await supabase.from("app_users").update({ is_blocked: false }).eq("id", userId);
    return !error;
  },

  async deleteUser(userId: string): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    const { error } = await supabase.from("app_users").delete().eq("id", userId);
    return !error;
  },

  async getDepositRequests(status?: "pending" | "accepted" | "rejected"): Promise<DbDepositRequest[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    let q = supabase.from("app_deposit_requests").select("*").order("created_at", { ascending: false });
    if (status) q = q.eq("status", status);
    const { data } = await q;
    return (data ?? []).map(toDepositRequest);
  },

  async getDepositRequest(id: string): Promise<DbDepositRequest | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data } = await supabase.from("app_deposit_requests").select("*").eq("id", id).single();
    return data ? toDepositRequest(data) : null;
  },

  async getDepositRequestsByUser(userId: string): Promise<DbDepositRequest[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const { data } = await supabase
      .from("app_deposit_requests")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });
    return (data ?? []).map(toDepositRequest);
  },

  async addDepositRequest(userId: string, amount: number, utr: string): Promise<DbDepositRequest | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: existing } = await supabase
      .from("app_deposit_requests")
      .select("id")
      .eq("utr", utr.trim())
      .limit(1)
      .maybeSingle();
    if (existing) return null;
    const { data, error } = await supabase
      .from("app_deposit_requests")
      .insert({ user_id: userId, amount, utr, status: "pending" })
      .select()
      .single();
    if (error) return null;
    return toDepositRequest(data);
  },

  async acceptDepositRequest(id: string): Promise<DbDepositRequest | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: req } = await supabase.from("app_deposit_requests").select("*").eq("id", id).eq("status", "pending").single();
    if (!req) return null;
    await supabase.from("app_deposit_requests").update({ status: "accepted" }).eq("id", id);
    const { data: user } = await supabase.from("app_users").select("coins").eq("id", req.user_id).single();
    if (user) {
      await supabase.from("app_users").update({ coins: user.coins + req.amount }).eq("id", req.user_id);
      await supabase.from("app_coin_transactions").insert({
        user_id: req.user_id,
        amount: req.amount,
        type: "deposit",
        description: "Deposited",
        reference_text: req.utr,
      });
    }
    return db.getDepositRequest(id);
  },

  async rejectDepositRequest(id: string): Promise<DbDepositRequest | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: req } = await supabase.from("app_deposit_requests").select("*").eq("id", id).eq("status", "pending").single();
    if (!req) return null;
    await supabase.from("app_deposit_requests").update({ status: "rejected" }).eq("id", id);
    await supabase.from("app_coin_transactions").insert({
      user_id: req.user_id,
      amount: req.amount,
      type: "deposit_failed",
      description: "Deposit rejected",
      reference_text: req.utr,
    });
    return db.getDepositRequest(id);
  },

  async blockDepositRequest(id: string): Promise<DbDepositRequest | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: req } = await supabase.from("app_deposit_requests").select("*").eq("id", id).eq("status", "pending").single();
    if (!req) return null;
    await supabase.from("app_deposit_requests").update({ status: "rejected" }).eq("id", id);
    await supabase.from("app_users").update({ is_blocked: true }).eq("id", req.user_id);
    await supabase.from("app_coin_transactions").insert({
      user_id: req.user_id,
      amount: req.amount,
      type: "deposit_failed",
      description: "Deposit rejected (user blocked)",
      reference_text: req.utr,
    });
    return db.getDepositRequest(id);
  },

  async getWithdrawalCharge(): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;
    const { data, error } = await supabase.from("app_settings").select("value").eq("key", "withdrawal_charge").maybeSingle();
    if (error || !data?.value) return 0;
    const n = Number(String(data.value).trim());
    return Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : 0;
  },

  async setWithdrawalCharge(percent: number): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;
    const p = Math.max(0, Math.min(100, percent));
    await supabase.from("app_settings").upsert({ key: "withdrawal_charge", value: String(p), updated_at: new Date().toISOString() }, { onConflict: "key" });
    return p;
  },

  async getWithdrawalRequests(status?: "pending" | "accepted" | "rejected"): Promise<DbWithdrawalRequest[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    let q = supabase.from("app_withdrawal_requests").select("*").order("created_at", { ascending: false });
    if (status) q = q.eq("status", status);
    const { data } = await q;
    return (data ?? []).map(toWithdrawalRequest);
  },

  async getWithdrawalRequest(id: string): Promise<DbWithdrawalRequest | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data } = await supabase.from("app_withdrawal_requests").select("*").eq("id", id).single();
    return data ? toWithdrawalRequest(data) : null;
  },

  async getWithdrawalRequestsByUser(userId: string): Promise<DbWithdrawalRequest[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const { data } = await supabase.from("app_withdrawal_requests").select("*").eq("user_id", userId).order("created_at", { ascending: false });
    return (data ?? []).map(toWithdrawalRequest);
  },

  async addWithdrawalRequest(userId: string, amount: number, upiId: string): Promise<DbWithdrawalRequest | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: user } = await supabase.from("app_users").select("coins").eq("id", userId).single();
    if (!user || user.coins < amount) return null;
    const charge = await db.getWithdrawalCharge();
    await supabase.from("app_users").update({ coins: user.coins - amount }).eq("id", userId);
    const { data, error } = await supabase
      .from("app_withdrawal_requests")
      .insert({ user_id: userId, amount, upi_id: upiId, status: "pending", charge_percent: charge })
      .select()
      .single();
    if (error) {
      await supabase.from("app_users").update({ coins: user.coins }).eq("id", userId);
      return null;
    }
    return toWithdrawalRequest(data);
  },

  async acceptWithdrawalRequest(id: string): Promise<DbWithdrawalRequest | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: req } = await supabase.from("app_withdrawal_requests").select("*").eq("id", id).eq("status", "pending").single();
    if (!req) return null;
    await supabase.from("app_withdrawal_requests").update({ status: "accepted" }).eq("id", id);
    await supabase.from("app_coin_transactions").insert({
      user_id: req.user_id,
      amount: -req.amount,
      type: "withdraw",
      description: "Withdraw",
      reference_text: req.upi_id,
    });
    return db.getWithdrawalRequest(id);
  },

  async rejectWithdrawalRequest(id: string, note: string): Promise<DbWithdrawalRequest | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: req } = await supabase.from("app_withdrawal_requests").select("*").eq("id", id).eq("status", "pending").single();
    if (!req) return null;
    const { data: user } = await supabase.from("app_users").select("coins").eq("id", req.user_id).single();
    if (user) {
      await supabase.from("app_users").update({ coins: user.coins + req.amount }).eq("id", req.user_id);
    }
    await supabase.from("app_withdrawal_requests").update({ status: "rejected", reject_note: note }).eq("id", id);
    await supabase.from("app_coin_transactions").insert({
      user_id: req.user_id,
      amount: req.amount,
      type: "refund",
      description: note?.trim() ? `Withdrawal rejected: ${note.trim()}` : "Withdrawal rejected - refunded",
      reference_text: req.upi_id,
    });
    return db.getWithdrawalRequest(id);
  },

  async transactions(userId?: string): Promise<DbCoinTransaction[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    let q = supabase.from("app_coin_transactions").select("*").order("created_at", { ascending: false });
    if (userId) q = q.eq("user_id", userId);
    const { data } = await q;
    return (data ?? []).map(toTransaction);
  },

  async getSignupBonus(): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;
    const { data } = await supabase.from("app_settings").select("value").eq("key", "signup_bonus").single();
    return data?.value ? parseInt(data.value, 10) : 0;
  },

  async setSignupBonus(amount: number): Promise<number> {
    const supabase = getSupabase();
    if (!supabase) return 0;
    const a = Math.max(0, amount);
    await supabase.from("app_settings").upsert({ key: "signup_bonus", value: String(a), updated_at: new Date().toISOString() }, { onConflict: "key" });
    return a;
  },

  async getDepositQrUrl(): Promise<string | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data } = await supabase.from("app_settings").select("value").eq("key", "deposit_qr_url").single();
    return data?.value ?? null;
  },

  async setDepositQrUrl(url: string | null): Promise<string | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    await supabase.from("app_settings").upsert({ key: "deposit_qr_url", value: url ?? "", updated_at: new Date().toISOString() }, { onConflict: "key" });
    return url;
  },

  async getCustomerSupportUrl(): Promise<string | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data, error } = await supabase.from("app_settings").select("value").eq("key", "customer_support_url").maybeSingle();
    if (error) return null;
    const v = data?.value?.trim();
    return v || null;
  },

  async setCustomerSupportUrl(url: string | null): Promise<string | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    await supabase.from("app_settings").upsert({ key: "customer_support_url", value: url ?? "", updated_at: new Date().toISOString() }, { onConflict: "key" });
    return url || null;
  },

  async games(adminId?: string): Promise<{ id: string; name: string; imageUrl: string | null }[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const q = supabase.from("games").select("id, name, image_url").order("display_order").order("created_at");
    const { data, error } = await q;
    if (error) return [];
    let list = (data ?? []).map((r) => ({ id: r.id, name: r.name, imageUrl: r.image_url ?? null }));
    if (adminId) {
      const admin = await db.getAdminById(adminId);
      if (admin && admin.gamesAccessType === "specific" && !admin.isMasterAdmin && admin.allowedGameIds.length > 0) {
        list = list.filter((g) => admin.allowedGameIds.includes(g.id));
      }
    }
    return list;
  },

  async gameModes(gameId?: string): Promise<{ id: string; gameId: string; name: string; imageUrl: string | null }[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    let q = supabase.from("game_modes").select("id, game_id, name, image_url").order("display_order").order("created_at");
    if (gameId) q = q.eq("game_id", gameId);
    const { data } = await q;
    return (data ?? []).map((r) => ({ id: r.id, gameId: r.game_id, name: r.name, imageUrl: r.image_url ?? null }));
  },

  async getMode(id: string): Promise<{ id: string; gameId: string; name: string; imageUrl: string | null } | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data } = await supabase.from("game_modes").select("id, game_id, name, image_url").eq("id", id).single();
    return data ? { id: data.id, gameId: data.game_id, name: data.name, imageUrl: data.image_url ?? null } : null;
  },

  async addGame(name: string, imageUrl: string | null): Promise<{ id: string; name: string; imageUrl: string | null } | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data, error } = await supabase.from("games").insert({ name, image_url: imageUrl }).select("id, name, image_url").single();
    if (error || !data) return null;
    return { id: data.id, name: data.name, imageUrl: data.image_url ?? null };
  },

  async deleteGame(id: string): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    const { error } = await supabase.from("games").delete().eq("id", id);
    return !error;
  },

  async renameGame(id: string, name: string): Promise<{ id: string; name: string; imageUrl: string | null } | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data, error } = await supabase.from("games").update({ name, updated_at: new Date().toISOString() }).eq("id", id).select("id, name, image_url").single();
    if (error || !data) return null;
    return { id: data.id, name: data.name, imageUrl: data.image_url ?? null };
  },

  async addGameMode(gameId: string, name: string, imageUrl: string | null): Promise<{ id: string; gameId: string; name: string; imageUrl: string | null } | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data, error } = await supabase.from("game_modes").insert({ game_id: gameId, name, image_url: imageUrl }).select("id, game_id, name, image_url").single();
    if (error || !data) return null;
    return { id: data.id, gameId: data.game_id, name: data.name, imageUrl: data.image_url ?? null };
  },

  async deleteGameMode(id: string): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    const { error } = await supabase.from("game_modes").delete().eq("id", id);
    return !error;
  },

  async renameGameMode(id: string, name: string): Promise<{ id: string; gameId: string; name: string; imageUrl: string | null } | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data, error } = await supabase.from("game_modes").update({ name, updated_at: new Date().toISOString() }).eq("id", id).select("id, game_id, name, image_url").single();
    if (error || !data) return null;
    return { id: data.id, gameId: data.game_id, name: data.name, imageUrl: data.image_url ?? null };
  },

  async matches(modeId?: string): Promise<DbMatch[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    let q = supabase.from("matches").select("*").order("starts_at", { ascending: true, nullsFirst: false });
    if (modeId) q = q.eq("game_mode_id", modeId);
    const { data } = await q;
    return (data ?? []).map(toMatch);
  },

  async addMatch(
    gameModeId: string,
    title: string,
    entryFee: number,
    maxParticipants: number,
    scheduledAt: string,
    matchType: string,
    prizePool: { coinsPerKill: number; totalPrizePool?: number; rankRewards: { fromRank: number; toRank: number; coins: number }[] }
  ): Promise<DbMatch | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data, error } = await supabase
      .from("matches")
      .insert({
        game_mode_id: gameModeId,
        title,
        entry_fee: entryFee,
        max_participants: maxParticipants,
        starts_at: scheduledAt || null,
        match_type: matchType || "solo",
        coins_per_kill: prizePool?.coinsPerKill ?? 5,
        total_prize_pool: prizePool?.totalPrizePool ?? 0,
        rank_rewards: prizePool?.rankRewards ?? [],
      })
      .select()
      .single();
    if (error || !data) return null;
    return toMatch(data);
  },

  async getMatch(id: string): Promise<(DbMatch & { participants?: { id: string; matchId: string; userId: string; teamMembers: { inGameName: string; inGameUid: string; kills?: number }[]; joinedAt: string; rank?: number }[] }) | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: matchRow, error } = await supabase.from("matches").select("*").eq("id", id).single();
    if (error || !matchRow) return null;
    const { data: parts } = await supabase
      .from("match_participants")
      .select("id, match_id, user_id, in_game_name, in_game_uid, kills, squad_rank, joined_at")
      .eq("match_id", id)
      .order("joined_at", { ascending: true });
    const { data: appParts, error: appPartsError } = await supabase
      .from("app_match_participants")
      .select("id, match_id, app_user_id, in_game_name, in_game_uid, kills, squad_rank, joined_at")
      .eq("match_id", id)
      .order("joined_at", { ascending: true });
    const appPartsSafe = appPartsError ? [] : (appParts ?? []);
    const participants = [
      ...(parts ?? []).map((p) => ({
        id: p.id,
        matchId: p.match_id,
        userId: p.user_id,
        teamMembers: [{ inGameName: p.in_game_name, inGameUid: p.in_game_uid, kills: p.kills ?? 0 }],
        joinedAt: p.joined_at,
        rank: p.squad_rank ?? undefined,
      })),
      ...appPartsSafe.map((p) => ({
        id: p.id,
        matchId: p.match_id,
        userId: p.app_user_id,
        teamMembers: [{ inGameName: p.in_game_name, inGameUid: p.in_game_uid, kills: (p as { kills?: number }).kills ?? 0 }],
        joinedAt: p.joined_at,
        rank: (p as { squad_rank?: number }).squad_rank ?? undefined,
      })),
    ];
    return { ...toMatch(matchRow), participants };
  },

  async joinMatch(
    matchId: string,
    appUserId: string,
    inGameName: string,
    inGameUid: string,
    teamMembers?: { inGameName: string; inGameUid: string }[]
  ): Promise<{ error?: string } | null> {
    const supabase = getSupabase();
    if (!supabase) return { error: "Database not configured" };
    const { data: match } = await supabase.from("matches").select("*").eq("id", matchId).single();
    if (!match) return { error: "Match not found" };
    if (match.status !== "upcoming") return { error: "Registration closed" };
    if (match.registration_locked) return { error: "Registration locked" };
    const { data: user } = await supabase.from("app_users").select("coins, is_blocked").eq("id", appUserId).single();
    if (!user) return { error: "User not found" };
    if (user.is_blocked) return { error: "Account is blocked" };
    const entryFee = match.entry_fee ?? 0;
    if (user.coins < entryFee) return { error: "Insufficient coins" };
    const { data: existing } = await supabase
      .from("app_match_participants")
      .select("id")
      .eq("match_id", matchId)
      .eq("app_user_id", appUserId)
      .single();
    if (existing) return { error: "Already registered" };
    const { count: appCount } = await supabase.from("app_match_participants").select("id", { count: "exact", head: true }).eq("match_id", matchId);
    const { count: authCount } = await supabase.from("match_participants").select("id", { count: "exact", head: true }).eq("match_id", matchId);
    const total = (appCount ?? 0) + (authCount ?? 0);
    if (total >= (match.max_participants ?? 100)) return { error: "Match is full" };
    const t2 = teamMembers?.[0];
    const t3 = teamMembers?.[1];
    const t4 = teamMembers?.[2];
    const { error: insertErr } = await supabase.from("app_match_participants").insert({
      match_id: matchId,
      app_user_id: appUserId,
      in_game_name: inGameName,
      in_game_uid: inGameUid,
      participant_2_name: t2?.inGameName ?? null,
      participant_2_uid: t2?.inGameUid ?? null,
      participant_3_name: t3?.inGameName ?? null,
      participant_3_uid: t3?.inGameUid ?? null,
      participant_4_name: t4?.inGameName ?? null,
      participant_4_uid: t4?.inGameUid ?? null,
    });
    if (insertErr) return { error: insertErr.message };
    if (entryFee > 0) {
      await supabase.from("app_users").update({ coins: user.coins - entryFee }).eq("id", appUserId);
      await supabase.from("app_coin_transactions").insert({
        user_id: appUserId,
        amount: -entryFee,
        type: "match_entry",
        reference_id: matchId,
        description: "Match entry fee",
      });
    }
    return null;
  },

  async updateMatchRoomInfo(id: string, roomCode: string, roomPassword: string): Promise<DbMatch | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data, error } = await supabase
      .from("matches")
      .update({ room_code: roomCode, room_password: roomPassword, updated_at: new Date().toISOString() })
      .eq("id", id)
      .eq("status", "upcoming")
      .select()
      .single();
    if (error || !data) return null;
    return toMatch(data);
  },

  async startMatch(id: string, roomCode?: string, roomPassword?: string): Promise<DbMatch | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: existing } = await supabase.from("matches").select("room_code, room_password, status").eq("id", id).single();
    if (!existing || existing.status !== "upcoming") return null;
    const rc = roomCode ?? existing.room_code;
    const rp = roomPassword ?? existing.room_password;
    if (!rc || !rp) return null;
    const { data, error } = await supabase
      .from("matches")
      .update({ status: "ongoing", room_code: rc, room_password: rp, registration_locked: true, updated_at: new Date().toISOString() })
      .eq("id", id)
      .eq("status", "upcoming")
      .select()
      .single();
    if (error || !data) return null;
    return toMatch(data);
  },

  async cancelMatch(id: string): Promise<DbMatch | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: m } = await supabase.from("matches").select("*").eq("id", id).eq("status", "upcoming").single();
    if (!m) return null;
    const { data, error } = await supabase
      .from("matches")
      .update({ status: "cancelled", updated_at: new Date().toISOString() })
      .eq("id", id)
      .eq("status", "upcoming")
      .select()
      .single();
    if (error || !data) return null;
    return toMatch(data);
  },

  async deleteMatch(id: string): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    const { error } = await supabase.from("matches").delete().eq("id", id);
    return !error;
  },

  async renameMatch(id: string, title: string): Promise<DbMatch | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data, error } = await supabase.from("matches").update({ title, updated_at: new Date().toISOString() }).eq("id", id).select().single();
    if (error || !data) return null;
    return toMatch(data);
  },

  async updateParticipantKills(
    matchId: string,
    participantId: string,
    kills: number[]
  ): Promise<{ id: string } | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const k0 = kills[0] ?? 0;
    const { data: mp } = await supabase.from("match_participants").select("id").eq("id", participantId).eq("match_id", matchId).single();
    if (mp) {
      const { error } = await supabase.from("match_participants").update({ kills: k0 }).eq("id", participantId).eq("match_id", matchId);
      return error ? null : { id: participantId };
    }
    const { data: amp } = await supabase.from("app_match_participants").select("id").eq("id", participantId).eq("match_id", matchId).single();
    if (amp) {
      const { error } = await supabase.from("app_match_participants").update({ kills: k0 }).eq("id", participantId).eq("match_id", matchId);
      return error ? null : { id: participantId };
    }
    return null;
  },

  async updateParticipantRank(
    matchId: string,
    participantId: string,
    rank: number
  ): Promise<{ id: string } | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: mp } = await supabase.from("match_participants").select("id").eq("id", participantId).eq("match_id", matchId).single();
    if (mp) {
      const { error } = await supabase.from("match_participants").update({ squad_rank: rank }).eq("id", participantId).eq("match_id", matchId);
      return error ? null : { id: participantId };
    }
    const { data: amp } = await supabase.from("app_match_participants").select("id").eq("id", participantId).eq("match_id", matchId).single();
    if (amp) {
      const { error } = await supabase.from("app_match_participants").update({ squad_rank: rank }).eq("id", participantId).eq("match_id", matchId);
      return error ? null : { id: participantId };
    }
    return null;
  },

  async finishMatch(id: string): Promise<DbMatch | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const match = await db.getMatch(id);
    if (!match || match.status !== "ongoing") return null;
    const participants = match.participants ?? [];
    const prizePool = match.prizePool ?? { coinsPerKill: 0, totalPrizePool: 0, rankRewards: [] };
    const rewards = prizePool.rankRewards ?? [];
    const cpk = prizePool.coinsPerKill ?? 0;
    const withRank = participants
      .filter((p) => typeof p.rank === "number" && p.rank >= 1)
      .sort((a, b) => (a.rank ?? 0) - (b.rank ?? 0));
    for (const p of withRank) {
      const totalKills = (p.teamMembers ?? []).reduce((s, t) => s + (t.kills ?? 0), 0);
      let coins = totalKills * cpk;
      for (const r of rewards) {
        if (p.rank! >= r.fromRank && p.rank! <= r.toRank) {
          coins += r.coins;
          break;
        }
      }
      if (coins > 0 && p.userId) {
        await db.addMatchWinnings(p.userId, coins, id);
      }
    }
    const { data, error } = await supabase
      .from("matches")
      .update({ status: "completed", updated_at: new Date().toISOString() })
      .eq("id", id)
      .eq("status", "ongoing")
      .select()
      .single();
    if (error || !data) return null;
    return toMatch(data);
  },

  async loginAdmin(adminname: string, password: string): Promise<DbAdmin | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: admin } = await supabase.from("admins").select("*").ilike("adminname", adminname).single();
    if (!admin || !admin.password_hash) return null;
    const ok = await bcrypt.compare(password, admin.password_hash);
    if (!ok) return null;
    const { data: games } = await supabase.from("admin_allowed_games").select("game_id").eq("admin_id", admin.id);
    const allowedGameIds = (games ?? []).map((g) => g.game_id);
    return {
      id: admin.id,
      adminname: admin.adminname,
      passwordHash: admin.password_hash,
      isMasterAdmin: admin.is_master_admin ?? false,
      usersAccess: admin.users_access ?? false,
      coinsAccess: admin.coins_access ?? false,
      gamesAccessType: (admin.games_access_type as "all" | "specific") ?? "all",
      allowedGameIds,
      createdAt: admin.created_at,
    };
  },

  async getAdminById(id: string): Promise<DbAdmin | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: admin } = await supabase.from("admins").select("*").eq("id", id).single();
    if (!admin) return null;
    const { data: games } = await supabase.from("admin_allowed_games").select("game_id").eq("admin_id", admin.id);
    return {
      id: admin.id,
      adminname: admin.adminname,
      passwordHash: "[hidden]",
      isMasterAdmin: admin.is_master_admin ?? false,
      usersAccess: admin.users_access ?? false,
      coinsAccess: admin.coins_access ?? false,
      gamesAccessType: (admin.games_access_type as "all" | "specific") ?? "all",
      allowedGameIds: (games ?? []).map((g) => g.game_id),
      createdAt: admin.created_at,
    };
  },

  async getAllAdmins(): Promise<DbAdmin[]> {
    const supabase = getSupabase();
    if (!supabase) return [];
    const { data: admins } = await supabase.from("admins").select("*").not("adminname", "is", null);
    if (!admins) return [];
    const result: DbAdmin[] = [];
    for (const a of admins) {
      const { data: games } = await supabase.from("admin_allowed_games").select("game_id").eq("admin_id", a.id);
      result.push({
        id: a.id,
        adminname: a.adminname ?? "",
        passwordHash: "[hidden]",
        isMasterAdmin: a.is_master_admin ?? false,
        usersAccess: a.users_access ?? false,
        coinsAccess: a.coins_access ?? false,
        gamesAccessType: (a.games_access_type as "all" | "specific") ?? "all",
        allowedGameIds: (games ?? []).map((g) => g.game_id),
        createdAt: a.created_at,
      });
    }
    return result;
  },

  async createAdmin(
    adminname: string,
    password: string,
    opts: { usersAccess: boolean; coinsAccess: boolean; gamesAccessType: "all" | "specific"; allowedGameIds: string[] }
  ): Promise<DbAdmin | null> {
    const supabase = getSupabase();
    if (!supabase) return null;
    const { data: existing } = await supabase.from("admins").select("id").ilike("adminname", adminname).single();
    if (existing) return null;
    const hash = bcrypt.hashSync(password, 10);
    const { data: admin, error } = await supabase
      .from("admins")
      .insert({
        adminname,
        password_hash: hash,
        is_master_admin: false,
        users_access: opts.usersAccess,
        coins_access: opts.coinsAccess,
        games_access_type: opts.gamesAccessType,
      })
      .select()
      .single();
    if (error || !admin) return null;
    if (opts.gamesAccessType === "specific" && opts.allowedGameIds?.length) {
      await supabase.from("admin_allowed_games").insert(opts.allowedGameIds.map((gid) => ({ admin_id: admin.id, game_id: gid })));
    }
    return db.getAdminById(admin.id);
  },

  async deleteAdmin(adminId: string): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    const { data: admin } = await supabase.from("admins").select("is_master_admin").eq("id", adminId).single();
    if (!admin || admin.is_master_admin) return false;
    await supabase.from("admin_allowed_games").delete().eq("admin_id", adminId);
    const { error } = await supabase.from("admins").delete().eq("id", adminId);
    return !error;
  },

  async updateAdminPassword(adminId: string, newPassword: string): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    const hash = bcrypt.hashSync(newPassword, 10);
    const { error } = await supabase.from("admins").update({ password_hash: hash }).eq("id", adminId);
    return !error;
  },
};

export function isDbConfigured(): boolean {
  return !!(process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY);
}
