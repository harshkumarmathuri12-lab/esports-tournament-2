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
  if (!modeId) {
    return NextResponse.json({ error: "modeId required" }, { status: 400, headers: NO_STORE });
  }
  const store = getStore();
  const matches = await store.matches(modeId);
  // Map scheduledAt to startsAt for Android app compatibility
  const withStartsAt = matches.map((m) => ({ ...m, startsAt: m.scheduledAt }));
  return NextResponse.json(withStartsAt, { headers: NO_STORE });
}
