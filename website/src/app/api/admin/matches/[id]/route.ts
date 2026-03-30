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

export async function GET(
  _request: Request,
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
  return NextResponse.json(match);
}

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { id } = await params;
  if (!(await checkMatchAccess(admin.id, id))) {
    return NextResponse.json({ error: "No access to this match" }, { status: 403 });
  }
  const store = getStore();
  const ok = await store.deleteMatch(id);
  if (!ok) return NextResponse.json({ error: "Match not found" }, { status: 404 });
  return NextResponse.json({ success: true });
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { id } = await params;
  if (!(await checkMatchAccess(admin.id, id))) {
    return NextResponse.json({ error: "No access to this match" }, { status: 403 });
  }
  const body = await request.json();
  const store = getStore();
  const match = await store.getMatch(id);
  if (!match) return NextResponse.json({ error: "Match not found" }, { status: 404 });

  if (body.title != null && typeof body.title === "string") {
    await store.renameMatch(id, body.title);
  }
  if (match.status === "upcoming" && body.roomCode != null && body.roomPassword != null) {
    const updated = await store.updateMatchRoomInfo(id, String(body.roomCode), String(body.roomPassword));
    if (updated) {
      const full = await store.getMatch(id);
      return NextResponse.json(full!);
    }
  }
  const updated = await store.getMatch(id);
  return NextResponse.json(updated!);
}
