import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

export async function GET(request: Request) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { searchParams } = new URL(request.url);
  const gameId = searchParams.get("gameId");
  if (gameId && admin.gamesAccessType === "specific" && !admin.isMasterAdmin) {
    if (!admin.allowedGameIds.includes(gameId)) {
      return NextResponse.json({ error: "No access to this game" }, { status: 403 });
    }
  }
  const store = getStore();
  const modes = await store.gameModes(gameId ?? undefined);
  return NextResponse.json(modes);
}

export async function POST(request: Request) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const store = getStore();
  if (!(await store.canAccessGames(admin.id))) {
    return NextResponse.json({ error: "No games access" }, { status: 403 });
  }
  const { gameId, name, imageUrl } = await request.json();
  if (!gameId || !name) {
    return NextResponse.json(
      { error: "gameId and name are required" },
      { status: 400 }
    );
  }
  if (admin.gamesAccessType === "specific" && !admin.isMasterAdmin && !admin.allowedGameIds.includes(gameId)) {
    return NextResponse.json({ error: "No access to this game" }, { status: 403 });
  }
  const mode = await store.addGameMode(gameId, name, imageUrl ?? null);
  return NextResponse.json(mode);
}
