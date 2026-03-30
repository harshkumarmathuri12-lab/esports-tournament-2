import { unstable_noStore } from "next/cache";
import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";

export const dynamic = "force-dynamic";

const NO_STORE = {
  "Cache-Control": "no-store, no-cache, must-revalidate",
  Pragma: "no-cache",
} as const;

export async function GET() {
  unstable_noStore();
  const chargePercent = await getStore().getWithdrawalCharge();
  return NextResponse.json({ chargePercent }, { headers: NO_STORE });
}
