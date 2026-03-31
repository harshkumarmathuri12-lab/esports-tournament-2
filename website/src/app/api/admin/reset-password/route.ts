import { NextResponse } from "next/server";

import { isDbConfigured } from "@/lib/db";
import { getStore } from "@/lib/store";

const RESET_PASSWORD = "admin123";

export async function POST() {
  const store = getStore();
  const admins = await store.getAllAdmins();
  const admin = admins.find((item) => item.isMasterAdmin) ?? admins[0];

  console.info(
    isDbConfigured()
      ? 'Admin password is stored in the database table "admins".'
      : 'Admin password is stored in memory via src/lib/admin-store.ts.'
  );

  if (!admin) {
    return NextResponse.json({ error: "No admin found to reset" }, { status: 404 });
  }

  const updated = await store.updateAdminPassword(admin.id, RESET_PASSWORD);

  if (!updated) {
    return NextResponse.json({ error: "Failed to reset admin password" }, { status: 500 });
  }

  return NextResponse.json({ message: "Admin password reset successful" });
}
