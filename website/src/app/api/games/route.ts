import { unstable_noStore } from "next/cache";
import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";

/** Always read from DB — do not freeze the list at build time */
export const dynamic = "force-dynamic";

const NO_STORE = {
  "Cache-Control": "no-store, no-cache, must-revalidate",
  Pragma: "no-cache",
} as const;

export async function GET() {
  unstable_noStore();
  const store = getStore();
  const games = await store.games();
  return NextResponse.json(games, { headers: NO_STORE });
}
