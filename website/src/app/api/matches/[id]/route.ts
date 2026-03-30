import { unstable_noStore } from "next/cache";
import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";

export const dynamic = "force-dynamic";

const NO_STORE = {
  "Cache-Control": "no-store, no-cache, must-revalidate",
  Pragma: "no-cache",
} as const;

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  unstable_noStore();
  const { id } = await params;
  const store = getStore();
  const match = await store.getMatch(id);
  if (!match) return NextResponse.json({ error: "Match not found" }, { status: 404 });
  const { participants: _p, ...matchWithoutParticipants } = match;
  return NextResponse.json({ ...matchWithoutParticipants, startsAt: match.scheduledAt }, { headers: NO_STORE });
}
