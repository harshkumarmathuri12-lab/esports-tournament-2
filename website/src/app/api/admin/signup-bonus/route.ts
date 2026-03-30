import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

export async function GET() {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!admin.usersAccess && !admin.coinsAccess) return NextResponse.json({ error: "No access" }, { status: 403 });
  const signupBonus = await getStore().getSignupBonus();
  return NextResponse.json({ signupBonus });
}

export async function PATCH(request: Request) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!admin.usersAccess && !admin.coinsAccess) return NextResponse.json({ error: "No access" }, { status: 403 });
  try {
    const body = await request.json();
    const amount = Number(body.signupBonus);
    if (isNaN(amount) || amount < 0) {
      return NextResponse.json({ error: "Amount must be 0 or greater" }, { status: 400 });
    }
    const signupBonus = await getStore().setSignupBonus(amount);
    return NextResponse.json({ signupBonus });
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
}
