import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

export async function GET(request: Request) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!admin.coinsAccess) return NextResponse.json({ error: "No coins access" }, { status: 403 });
  const { searchParams } = new URL(request.url);
  const status = searchParams.get("status") as "pending" | "accepted" | "rejected" | null;
  const store = getStore();
  const [requests, users] = await Promise.all([store.getDepositRequests(status ?? undefined), store.users()]);
  const withUser = requests.map((r) => ({
    ...r,
    user: users.find((u) => u.id === r.userId),
  }));
  return NextResponse.json(withUser);
}
