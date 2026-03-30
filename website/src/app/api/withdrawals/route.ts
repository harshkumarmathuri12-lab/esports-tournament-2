import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAppUserId } from "@/lib/app-auth";

const MAX_WITHDRAW = 1_000_000;

export async function POST(request: Request) {
  try {
    const userId = await getAppUserId();
    if (!userId) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const body = await request.json();
    const { amount, upiId } = body;
    if (!upiId || typeof upiId !== "string" || !upiId.trim()) {
      return NextResponse.json({ error: "UPI ID required" }, { status: 400 });
    }
    if (upiId.length > 100) {
      return NextResponse.json({ error: "UPI ID too long" }, { status: 400 });
    }
    const num = Number(amount);
    if (isNaN(num) || num <= 0) {
      return NextResponse.json({ error: "amount must be a positive number" }, { status: 400 });
    }
    if (num > MAX_WITHDRAW) {
      return NextResponse.json({ error: "Amount exceeds maximum" }, { status: 400 });
    }

    const store = getStore();
    const user = await store.getUser(userId);
    if (!user) return NextResponse.json({ error: "User not found" }, { status: 404 });
    if (user.isBlocked) return NextResponse.json({ error: "Account is blocked" }, { status: 403 });

    const req = await store.addWithdrawalRequest(userId, num, upiId.trim());
    if (!req) return NextResponse.json({ error: "Failed to create withdrawal request" }, { status: 400 });
    return NextResponse.json(req);
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
}
