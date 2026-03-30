import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

export async function GET() {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!admin.coinsAccess) return NextResponse.json({ error: "No coins access" }, { status: 403 });
  const url = await getStore().getDepositQrUrl();
  return NextResponse.json({ url });
}

export async function PATCH(request: Request) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!admin.coinsAccess) return NextResponse.json({ error: "No coins access" }, { status: 403 });
  const body = await request.json().catch(() => ({}));
  const url = typeof body.url === "string" ? body.url : null;
  const store = getStore();
  await store.setDepositQrUrl(url);
  const updated = await store.getDepositQrUrl();
  return NextResponse.json({ url: updated });
}
