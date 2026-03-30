import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

async function checkModeAccess(adminId: string, modeId: string): Promise<boolean> {
  const store = getStore();
  const [admin, mode] = await Promise.all([store.getAdminById(adminId), store.getMode(modeId)]);
  if (!admin || !mode) return false;
  if (admin.isMasterAdmin || admin.gamesAccessType === "all") return true;
  return admin.allowedGameIds.includes(mode.gameId);
}

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { id } = await params;
  if (!(await checkModeAccess(admin.id, id))) {
    return NextResponse.json({ error: "No access to this mode" }, { status: 403 });
  }
  const store = getStore();
  const ok = await store.deleteMode(id);
  if (!ok) return NextResponse.json({ error: "Mode not found" }, { status: 404 });
  return NextResponse.json({ success: true });
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { id } = await params;
  if (!(await checkModeAccess(admin.id, id))) {
    return NextResponse.json({ error: "No access to this mode" }, { status: 403 });
  }
  const { name } = await request.json();
  if (!name || typeof name !== "string") {
    return NextResponse.json({ error: "name is required" }, { status: 400 });
  }
  const store = getStore();
  const mode = await store.renameMode(id, name);
  if (!mode) return NextResponse.json({ error: "Mode not found" }, { status: 404 });
  return NextResponse.json(mode);
}
