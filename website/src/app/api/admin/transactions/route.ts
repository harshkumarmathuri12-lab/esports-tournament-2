import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

export async function GET(request: Request) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!admin.coinsAccess) return NextResponse.json({ error: "No coins access" }, { status: 403 });
  const { searchParams } = new URL(request.url);
  const userId = searchParams.get("userId") ?? undefined;
  const transactions = await getStore().transactions(userId);
  return NextResponse.json(transactions);
}
