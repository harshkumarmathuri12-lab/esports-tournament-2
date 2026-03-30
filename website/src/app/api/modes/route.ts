import { unstable_noStore } from "next/cache";
import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";

export const dynamic = "force-dynamic";

const NO_STORE = {
  "Cache-Control": "no-store, no-cache, must-revalidate",
  Pragma: "no-cache",
} as const;

export async function GET(request: Request) {
  unstable_noStore();
  const { searchParams } = new URL(request.url);
  const modeId = searchParams.get("modeId");
  if (modeId) {
    const store = getStore();
    const mode = await store.getMode(modeId);
    if (!mode) return NextResponse.json({ error: "Mode not found" }, { status: 404, headers: NO_STORE });
    return NextResponse.json(mode, { headers: NO_STORE });
  }
  const gameId = searchParams.get("gameId");
  if (!gameId) {
    return NextResponse.json({ error: "gameId or modeId required" }, { status: 400, headers: NO_STORE });
  }
  const store = getStore();
  const modes = await store.gameModes(gameId);
  return NextResponse.json(modes, { headers: NO_STORE });
}
