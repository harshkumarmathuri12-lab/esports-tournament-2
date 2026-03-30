import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

export async function GET() {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!admin.coinsAccess) return NextResponse.json({ error: "No coins access" }, { status: 403 });
  const chargePercent = await getStore().getWithdrawalCharge();
  return NextResponse.json({ chargePercent });
}

export async function PATCH(request: Request) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!admin.coinsAccess) return NextResponse.json({ error: "No coins access" }, { status: 403 });
  try {
    const body = await request.json();
    const percent = Number(body.chargePercent);
    if (isNaN(percent) || percent < 0 || percent > 100) {
      return NextResponse.json({ error: "Charge must be 0-100" }, { status: 400 });
    }
    const chargePercent = await getStore().setWithdrawalCharge(percent);
    return NextResponse.json({ chargePercent });
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
}
