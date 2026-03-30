import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!admin.isMasterAdmin) return NextResponse.json({ error: "Master admin only" }, { status: 403 });
  const { id } = await params;
  const target = await getStore().getAdminById(id);
  if (!target) return NextResponse.json({ error: "Admin not found" }, { status: 404 });
  if (target.isMasterAdmin) return NextResponse.json({ error: "Cannot delete master admin" }, { status: 403 });
  const ok = await getStore().deleteAdmin(id);
  if (!ok) return NextResponse.json({ error: "Failed to delete admin" }, { status: 500 });
  return NextResponse.json({ success: true });
}
