import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

async function checkMatchAccess(adminId: string, matchId: string): Promise<boolean> {
  const store = getStore();
  const [admin, match] = await Promise.all([store.getAdminById(adminId), store.getMatch(matchId)]);
  if (!admin || !match) return false;
  const mode = await store.getMode(match.gameModeId);
  if (!mode) return false;
  if (admin.isMasterAdmin || admin.gamesAccessType === "all") return true;
  return admin.allowedGameIds.includes(mode.gameId);
}

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { id } = await params;
  if (!(await checkMatchAccess(admin.id, id))) {
    return NextResponse.json({ error: "No access to this match" }, { status: 403 });
  }
  const store = getStore();
  const match = await store.getMatch(id);
  if (!match) return NextResponse.json({ error: "Match not found" }, { status: 404 });
  let roomCode = match.roomCode;
  let roomPassword = match.roomPassword;
  try {
    const body = await request.json();
    if (body?.roomCode) roomCode = body.roomCode;
    if (body?.roomPassword) roomPassword = body.roomPassword;
  } catch {
    // No body - use room from match
  }
  if (!roomCode || !roomPassword) {
    return NextResponse.json(
      { error: "Room code and password must be set first. Update the match with room info, then start." },
      { status: 400 }
    );
  }
  const updated = await store.startMatch(id, roomCode, roomPassword);
  if (!updated) {
    return NextResponse.json({ error: "Match not found or not upcoming" }, { status: 404 });
  }
  const full = await store.getMatch(id);
  return NextResponse.json(full ?? updated);
}
