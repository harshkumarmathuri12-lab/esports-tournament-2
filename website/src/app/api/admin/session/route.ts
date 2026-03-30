import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { cookies } from "next/headers";

const SESSION_COOKIE = "admin_session";

export async function GET() {
  const cookieStore = await cookies();
  const sessionId = cookieStore.get(SESSION_COOKIE)?.value;
  if (!sessionId) {
    return NextResponse.json({ admin: null }, { status: 200 });
  }
  const admin = await getStore().getAdminById(sessionId);
  if (!admin) {
    return NextResponse.json({ admin: null }, { status: 200 });
  }
  return NextResponse.json({
    admin: {
      id: admin.id,
      adminname: admin.adminname,
      isMasterAdmin: admin.isMasterAdmin,
      usersAccess: admin.usersAccess,
      coinsAccess: admin.coinsAccess,
      gamesAccessType: admin.gamesAccessType,
      allowedGameIds: admin.allowedGameIds,
    },
  });
}
