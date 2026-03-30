import { unstable_noStore } from "next/cache";
import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

function canManageSupport(admin: { isMasterAdmin: boolean; usersAccess: boolean; coinsAccess: boolean }) {
  return admin.isMasterAdmin || admin.usersAccess || admin.coinsAccess;
}

export async function GET() {
  unstable_noStore();
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!canManageSupport(admin)) return NextResponse.json({ error: "No access" }, { status: 403 });
  const url = await getStore().getCustomerSupportUrl();
  return NextResponse.json({ url }, { headers: { "Cache-Control": "no-store" } });
}

export async function PATCH(request: Request) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!canManageSupport(admin)) return NextResponse.json({ error: "No access" }, { status: 403 });
  const body = await request.json().catch(() => ({}));
  const url = typeof body.url === "string" ? body.url.trim() || null : null;
  const store = getStore();
  await store.setCustomerSupportUrl(url);
  const updated = await store.getCustomerSupportUrl();
  return NextResponse.json({ url: updated });
}
