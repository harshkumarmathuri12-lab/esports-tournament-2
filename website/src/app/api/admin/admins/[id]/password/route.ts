import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!admin.isMasterAdmin) return NextResponse.json({ error: "Master admin only" }, { status: 403 });
  const { id } = await params;
  const body = await request.json();
  const { newPassword } = body;
  if (!newPassword || typeof newPassword !== "string" || newPassword.length < 6) {
    return NextResponse.json({ error: "Password must be at least 6 characters" }, { status: 400 });
  }
  const ok = await getStore().updateAdminPassword(id, newPassword);
  if (!ok) return NextResponse.json({ error: "Admin not found" }, { status: 404 });
  return NextResponse.json({ success: true });
}
