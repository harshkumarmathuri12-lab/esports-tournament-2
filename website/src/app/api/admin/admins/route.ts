import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

export async function GET() {
  const admin = await getAdminSession();
  if (!admin) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  if (!admin.isMasterAdmin) {
    return NextResponse.json({ error: "Master admin only" }, { status: 403 });
  }
  const admins = await getStore().getAllAdmins();
  return NextResponse.json(admins);
}

export async function POST(request: Request) {
  const admin = await getAdminSession();
  if (!admin || !admin.isMasterAdmin) {
    return NextResponse.json({ error: "Master admin only" }, { status: 403 });
  }
  const body = await request.json();
  const { adminname, password, usersAccess, coinsAccess, gamesAccessType, allowedGameIds } = body;
  if (!adminname || !password) {
    return NextResponse.json({ error: "Admin name and password required" }, { status: 400 });
  }
  const newAdmin = await getStore().createAdmin(adminname, password, {
    usersAccess: !!usersAccess,
    coinsAccess: !!coinsAccess,
    gamesAccessType: gamesAccessType === "specific" ? "specific" : "all",
    allowedGameIds: Array.isArray(allowedGameIds) ? allowedGameIds : [],
  });
  if (!newAdmin) {
    return NextResponse.json({ error: "Admin name already exists" }, { status: 400 });
  }
  return NextResponse.json({
    id: newAdmin.id,
    adminname: newAdmin.adminname,
    isMasterAdmin: newAdmin.isMasterAdmin,
    usersAccess: newAdmin.usersAccess,
    coinsAccess: newAdmin.coinsAccess,
    gamesAccessType: newAdmin.gamesAccessType,
    allowedGameIds: newAdmin.allowedGameIds,
    createdAt: newAdmin.createdAt,
  });
}
