/**
 * Unified store: uses Supabase db when configured, otherwise in-memory admin-store.
 * API routes should use getStore() and await the async methods.
 */

import { adminStore } from "./admin-store";
import { db, isDbConfigured } from "./db";

export function getStore() {
  if (isDbConfigured()) {
    return {
      loginAdmin: (adminname: string, password: string) => db.loginAdmin(adminname, password),
      getAdminById: (id: string) => db.getAdminById(id),
      games: (adminId?: string) => db.games(adminId),
      gameModes: (gameId?: string) => db.gameModes(gameId),
      addGame: (name: string, imageUrl: string | null) => db.addGame(name, imageUrl),
      deleteGame: (id: string) => db.deleteGame(id),
      renameGame: (id: string, name: string) => db.renameGame(id, name),
      addGameMode: (gameId: string, name: string, imageUrl: string | null) => db.addGameMode(gameId, name, imageUrl),
      deleteMode: (id: string) => db.deleteGameMode(id),
      renameMode: (id: string, name: string) => db.renameGameMode(id, name),
      getMode: (id: string) => db.getMode(id),
      canAccessGames: (adminId: string) =>
        db.getAdminById(adminId).then((a) => !!(a && (a.isMasterAdmin || a.gamesAccessType === "all" || a.allowedGameIds.length > 0))),
      matches: (modeId?: string) => db.matches(modeId),
      addMatch: (
        gameModeId: string,
        title: string,
        entryFee: number,
        maxParticipants: number,
        scheduledAt: string,
        matchType: string,
        prizePool: { coinsPerKill: number; totalPrizePool?: number; rankRewards: { fromRank: number; toRank: number; coins: number }[] }
      ) => db.addMatch(gameModeId, title, entryFee, maxParticipants, scheduledAt, matchType, prizePool),
      getMatch: (id: string) => db.getMatch(id),
      joinMatch: (
        matchId: string,
        appUserId: string,
        inGameName: string,
        inGameUid: string,
        teamMembers?: { inGameName: string; inGameUid: string }[]
      ) => db.joinMatch(matchId, appUserId, inGameName, inGameUid, teamMembers),
      updateMatchRoomInfo: (id: string, roomCode: string, roomPassword: string) => db.updateMatchRoomInfo(id, roomCode, roomPassword),
      startMatch: (id: string, roomCode?: string, roomPassword?: string) => db.startMatch(id, roomCode, roomPassword),
      cancelMatch: (id: string) => db.cancelMatch(id),
      finishMatch: (id: string) => db.finishMatch(id),
      deleteMatch: (id: string) => db.deleteMatch(id),
      renameMatch: (id: string, title: string) => db.renameMatch(id, title),
      updateParticipantKills: (matchId: string, participantId: string, kills: number[]) =>
        db.updateParticipantKills(matchId, participantId, kills),
      updateParticipantRank: (matchId: string, participantId: string, rank: number) =>
        db.updateParticipantRank(matchId, participantId, rank),
      users: () => db.users(),
      addUser: (email: string, displayName: string, password: string) => db.addUser(email, displayName, password),
      signInUser: (email: string, password: string) => db.signInUser(email, password),
      getUser: (id: string) => db.getUser(id),
      addCoins: (userId: string, amount: number, desc?: string) => db.addCoins(userId, amount, desc),
      blockUser: (userId: string) => db.blockUser(userId),
      unblockUser: (userId: string) => db.unblockUser(userId),
      deleteUser: (userId: string) => db.deleteUser(userId),
      getDepositRequests: (status?: "pending" | "accepted" | "rejected") => db.getDepositRequests(status),
      getDepositRequest: (id: string) => db.getDepositRequest(id),
      getDepositRequestsByUser: (userId: string) => db.getDepositRequestsByUser(userId),
      addDepositRequest: (userId: string, amount: number, utr: string) => db.addDepositRequest(userId, amount, utr),
      acceptDepositRequest: (id: string) => db.acceptDepositRequest(id),
      rejectDepositRequest: (id: string) => db.rejectDepositRequest(id),
      blockDepositRequest: (id: string) => db.blockDepositRequest(id),
      getWithdrawalCharge: () => db.getWithdrawalCharge(),
      setWithdrawalCharge: (p: number) => db.setWithdrawalCharge(p),
      getWithdrawalRequests: (status?: "pending" | "accepted" | "rejected") => db.getWithdrawalRequests(status),
      getWithdrawalRequest: (id: string) => db.getWithdrawalRequest(id),
      getWithdrawalRequestsByUser: (userId: string) => db.getWithdrawalRequestsByUser(userId),
      addWithdrawalRequest: (userId: string, amount: number, upiId: string) => db.addWithdrawalRequest(userId, amount, upiId),
      acceptWithdrawalRequest: (id: string) => db.acceptWithdrawalRequest(id),
      rejectWithdrawalRequest: (id: string, note: string) => db.rejectWithdrawalRequest(id, note),
      transactions: (userId?: string) => db.transactions(userId),
      getSignupBonus: () => db.getSignupBonus(),
      setSignupBonus: (a: number) => db.setSignupBonus(a),
      getDepositQrUrl: () => db.getDepositQrUrl(),
      setDepositQrUrl: (url: string | null) => db.setDepositQrUrl(url),
      getCustomerSupportUrl: () => db.getCustomerSupportUrl(),
      setCustomerSupportUrl: (url: string | null) => db.setCustomerSupportUrl(url),
      getAllAdmins: () => db.getAllAdmins(),
      createAdmin: (adminname: string, password: string, opts: { usersAccess: boolean; coinsAccess: boolean; gamesAccessType: "all" | "specific"; allowedGameIds: string[] }) =>
        db.createAdmin(adminname, password, opts),
      deleteAdmin: (id: string) => db.deleteAdmin(id),
      updateAdminPassword: (id: string, newPassword: string) => db.updateAdminPassword(id, newPassword),
    };
  }
  return {
    loginAdmin: (adminname: string, password: string) => adminStore.login(adminname, password),
    getAdminById: (id: string) => Promise.resolve(adminStore.getAdminById(id)),
    games: (adminId?: string) => Promise.resolve(adminStore.games(adminId)),
    gameModes: (gameId?: string) => Promise.resolve(adminStore.gameModes(gameId)),
    addGame: (name: string, imageUrl: string | null) => Promise.resolve(adminStore.addGame(name, imageUrl)),
    deleteGame: (id: string) => Promise.resolve(adminStore.deleteGame(id)),
    renameGame: (id: string, name: string) => Promise.resolve(adminStore.renameGame(id, name)),
    addGameMode: (gameId: string, name: string, imageUrl: string | null) => Promise.resolve(adminStore.addGameMode(gameId, name, imageUrl)),
    deleteMode: (id: string) => Promise.resolve(adminStore.deleteMode(id)),
    renameMode: (id: string, name: string) => Promise.resolve(adminStore.renameMode(id, name)),
    getMode: (id: string) => Promise.resolve(adminStore.getMode(id)),
    canAccessGames: (adminId: string) => Promise.resolve(adminStore.canAccessGames(adminId)),
    matches: (modeId?: string) => Promise.resolve(adminStore.matches(modeId)),
    addMatch: (
      gameModeId: string,
      title: string,
      entryFee: number,
      maxParticipants: number,
      scheduledAt: string,
      matchType: string,
      prizePool: { coinsPerKill: number; totalPrizePool?: number; rankRewards: { fromRank: number; toRank: number; coins: number }[] }
    ) => Promise.resolve(adminStore.addMatch(gameModeId, title, entryFee, maxParticipants, scheduledAt, matchType as "solo" | "duo" | "squad", prizePool)),
    getMatch: (id: string) => Promise.resolve(adminStore.getMatch(id)).then((m) => (m ? { ...m, participants: adminStore.getParticipantsForMatch(id) } : null)),
    joinMatch: (
      matchId: string,
      appUserId: string,
      inGameName: string,
      inGameUid: string,
      teamMembers?: { inGameName: string; inGameUid: string }[]
    ) => Promise.resolve(adminStore.joinMatch(matchId, appUserId, inGameName, inGameUid, teamMembers)),
    updateMatchRoomInfo: (id: string, roomCode: string, roomPassword: string) =>
      Promise.resolve(adminStore.updateMatchRoomInfo(id, roomCode, roomPassword)).then((m) => (m ? { ...m, participants: adminStore.getParticipantsForMatch(id) } : null)),
    startMatch: (id: string, roomCode?: string, roomPassword?: string) =>
      Promise.resolve(adminStore.startMatch(id, roomCode, roomPassword)).then((m) => (m ? { ...m, participants: adminStore.getParticipantsForMatch(id) } : null)),
    cancelMatch: (id: string) => Promise.resolve(adminStore.cancelMatch(id)).then((m) => (m ? { ...m, participants: adminStore.getParticipantsForMatch(id) } : null)),
    finishMatch: (id: string) => Promise.resolve(adminStore.finishMatch(id)).then((m) => (m ? { ...m, participants: adminStore.getParticipantsForMatch(id) } : null)),
    deleteMatch: (id: string) => Promise.resolve(adminStore.deleteMatch(id)),
    renameMatch: (id: string, title: string) => Promise.resolve(adminStore.renameMatch(id, title)),
    updateParticipantKills: (matchId: string, participantId: string, kills: number[]) =>
      Promise.resolve(adminStore.updateParticipantKills(matchId, participantId, kills)),
    updateParticipantRank: (matchId: string, participantId: string, rank: number) =>
      Promise.resolve(adminStore.updateParticipantRank(matchId, participantId, rank)),
    getAllAdmins: () => Promise.resolve(adminStore.getAllAdmins()),
    createAdmin: (adminname: string, password: string, opts: { usersAccess: boolean; coinsAccess: boolean; gamesAccessType: "all" | "specific"; allowedGameIds: string[] }) =>
      Promise.resolve(adminStore.createAdmin(adminname, password, opts)),
    deleteAdmin: (id: string) => Promise.resolve(adminStore.deleteAdmin(id)),
    updateAdminPassword: (id: string, newPassword: string) => Promise.resolve(adminStore.updateAdminPassword(id, newPassword)),
    users: () => Promise.resolve(adminStore.users()),
    addUser: (email: string, displayName: string, password: string) => Promise.resolve(adminStore.addUser(email, displayName, password)),
    signInUser: (email: string, password: string) => Promise.resolve(adminStore.signInUser(email, password)),
    getUser: (id: string) => Promise.resolve(adminStore.getUser(id)),
    addCoins: (userId: string, amount: number, desc?: string) => Promise.resolve(adminStore.addCoins(userId, amount, desc)),
    blockUser: (userId: string) => Promise.resolve(adminStore.blockUser(userId)),
    unblockUser: (userId: string) => Promise.resolve(adminStore.unblockUser(userId)),
    deleteUser: (userId: string) => Promise.resolve(adminStore.deleteUser(userId)),
    getDepositRequests: (status?: "pending" | "accepted" | "rejected") => Promise.resolve(adminStore.getDepositRequests(status)),
    getDepositRequest: (id: string) => Promise.resolve(adminStore.getDepositRequest(id)),
    getDepositRequestsByUser: (userId: string) => Promise.resolve(adminStore.getDepositRequestsByUser(userId)),
    addDepositRequest: (userId: string, amount: number, utr: string) => Promise.resolve(adminStore.addDepositRequest(userId, amount, utr)),
    acceptDepositRequest: (id: string) => Promise.resolve(adminStore.acceptDepositRequest(id)),
    rejectDepositRequest: (id: string) => Promise.resolve(adminStore.rejectDepositRequest(id)),
    blockDepositRequest: (id: string) => Promise.resolve(adminStore.blockDepositRequest(id)),
    getWithdrawalCharge: () => Promise.resolve(adminStore.getWithdrawalCharge()),
    setWithdrawalCharge: (p: number) => Promise.resolve(adminStore.setWithdrawalCharge(p)),
    getWithdrawalRequests: (status?: "pending" | "accepted" | "rejected") => Promise.resolve(adminStore.getWithdrawalRequests(status)),
    getWithdrawalRequest: (id: string) => Promise.resolve(adminStore.getWithdrawalRequest(id)),
    getWithdrawalRequestsByUser: (userId: string) => Promise.resolve(adminStore.getWithdrawalRequestsByUser(userId)),
    addWithdrawalRequest: (userId: string, amount: number, upiId: string) => Promise.resolve(adminStore.addWithdrawalRequest(userId, amount, upiId)),
    acceptWithdrawalRequest: (id: string) => Promise.resolve(adminStore.acceptWithdrawalRequest(id)),
    rejectWithdrawalRequest: (id: string, note: string) => Promise.resolve(adminStore.rejectWithdrawalRequest(id, note)),
    transactions: (userId?: string) => Promise.resolve(adminStore.transactions(userId)),
    getSignupBonus: () => Promise.resolve(adminStore.getSignupBonus()),
    setSignupBonus: (a: number) => Promise.resolve(adminStore.setSignupBonus(a)),
    getDepositQrUrl: () => Promise.resolve(adminStore.getDepositQrUrl()),
    setDepositQrUrl: (url: string | null) => Promise.resolve(adminStore.setDepositQrUrl(url)),
    getCustomerSupportUrl: () => Promise.resolve(adminStore.getCustomerSupportUrl()),
    setCustomerSupportUrl: (url: string | null) => Promise.resolve(adminStore.setCustomerSupportUrl(url)),
  };
}
