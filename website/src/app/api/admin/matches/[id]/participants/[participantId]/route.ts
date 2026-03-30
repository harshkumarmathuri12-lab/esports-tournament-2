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

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string; participantId: string }> }
) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { id: matchId, participantId } = await params;
  if (!(await checkMatchAccess(admin.id, matchId))) {
    return NextResponse.json({ error: "No access to this match" }, { status: 403 });
  }
  const store = getStore();
  const match = await store.getMatch(matchId);
  if (!match) return NextResponse.json({ error: "Match not found" }, { status: 404 });
  if (match.status !== "ongoing") {
    return NextResponse.json({ error: "Can only update participants during ongoing matches" }, { status: 400 });
  }
  const body = await request.json().catch(() => ({}));
  if (Array.isArray(body.kills)) {
    const updated = await store.updateParticipantKills(matchId, participantId, body.kills);
    if (!updated) return NextResponse.json({ error: "Participant not found" }, { status: 404 });
  }
  if (typeof body.rank === "number" && body.rank >= 1) {
    const participants = (match.participants ?? []);
    if (body.rank > participants.length) {
      return NextResponse.json({ error: "Invalid rank" }, { status: 400 });
    }
    const updated = await store.updateParticipantRank(matchId, participantId, body.rank);
    if (!updated) return NextResponse.json({ error: "Participant not found" }, { status: 404 });
  }
  const updatedMatch = await store.getMatch(matchId);
  return NextResponse.json(updatedMatch!);
}
