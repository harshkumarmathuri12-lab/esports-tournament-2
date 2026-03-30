import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

export async function GET() {
  try {
    const admin = await getAdminSession();
    if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const store = getStore();
    const games = await store.games(admin.id);
    return NextResponse.json(games);
  } catch {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
}

export async function POST(request: Request) {
  try {
    const admin = await getAdminSession();
    if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const store = getStore();
    if (!(await store.canAccessGames(admin.id))) {
      return NextResponse.json({ error: "No games access" }, { status: 403 });
    }
    const { name, imageUrl } = await request.json();
    if (!name || typeof name !== "string") {
      return NextResponse.json({ error: "name is required" }, { status: 400 });
    }
    const game = await store.addGame(name, imageUrl ?? null);
    return NextResponse.json(game);
  } catch {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
}
