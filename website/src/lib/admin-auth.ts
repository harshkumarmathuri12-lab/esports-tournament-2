import { cookies } from "next/headers";
import { getStore } from "@/lib/store";
import type { AdminPermission } from "@/lib/admin-store";

const SESSION_COOKIE = "admin_session";

export async function getAdminSession(): Promise<AdminPermission | null> {
  const cookieStore = await cookies();
  const sessionId = cookieStore.get(SESSION_COOKIE)?.value;
  if (!sessionId) return null;
  return await getStore().getAdminById(sessionId);
}

export async function requireAdmin(): Promise<AdminPermission> {
  const admin = await getAdminSession();
  if (!admin) {
    throw new Error("UNAUTHORIZED");
  }
  return admin;
}

export async function requireMasterAdmin(): Promise<AdminPermission> {
  const admin = await requireAdmin();
  if (!admin.isMasterAdmin) {
    throw new Error("FORBIDDEN");
  }
  return admin;
}
