import { NextResponse } from "next/server";

import { isDbConfigured } from "@/lib/db";
import { getStore } from "@/lib/store";

const RESET_PASSWORD = "admin123";

async function resetAdminPassword() {
  const store = getStore();
  const admins = await store.getAllAdmins();
  const admin = admins.find((item) => item.isMasterAdmin) ?? admins[0];

  console.info(
    isDbConfigured()
      ? 'Admin password is stored in the database table "admins".'
      : 'Admin password is stored in memory via src/lib/admin-store.ts.'
  );

  if (!admin) {
    return { ok: false as const, response: NextResponse.json({ error: "No admin found to reset" }, { status: 404 }) };
  }

  const updated = await store.updateAdminPassword(admin.id, RESET_PASSWORD);

  if (!updated) {
    return { ok: false as const, response: NextResponse.json({ error: "Failed to reset admin password" }, { status: 500 }) };
  }

  return { ok: true as const };
}

export async function GET() {
  const result = await resetAdminPassword();

  if (!result.ok) {
    return result.response;
  }

  return NextResponse.json({ message: "Admin password reset successful via GET" });
}

export async function POST() {
  const result = await resetAdminPassword();

  if (!result.ok) {
    return result.response;
  }

  return NextResponse.json({ message: "Admin password reset successful" });
}
