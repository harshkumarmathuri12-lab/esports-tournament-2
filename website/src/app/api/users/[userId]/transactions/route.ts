import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAppUserId } from "@/lib/app-auth";

export async function GET(_request: Request) {
  const userId = await getAppUserId();
  if (!userId) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const store = getStore();
  const [transactions, withdrawals, depositReqs] = await Promise.all([
    store.transactions(userId),
    store.getWithdrawalRequestsByUser(userId),
    store.getDepositRequestsByUser(userId),
  ]);

  const txItems = transactions.map((t) => {
    const isCredit = t.type === "admin_add" || t.type === "refund" || t.type === "deposit" || t.type === "signup_bonus";
    const isWithdraw = t.type === "withdraw" || t.type === "withdraw_failed";
    let status: "pending" | "successful" | "failed" | "refunded" | undefined;
    let note = t.description ?? t.type;
    if (t.type === "deposit") {
      status = "successful";
      note = "Deposit successful";
    } else if (t.type === "withdraw") {
      status = "successful";
      note = "Withdraw";
    } else if (t.type === "refund" && (t.description?.includes("Withdrawal") || t.description?.includes("refunded"))) {
      status = "refunded";
      note = t.description ?? "Withdrawal refunded";
    } else if (t.type === "withdraw_failed") {
      status = "refunded";
      note = t.description ?? "Withdrawal refunded";
    } else if (t.type === "deposit_failed") {
      status = "failed";
      note = t.description ?? "Deposit rejected";
    } else if (t.type === "admin_add") {
      note = t.description ?? "Admin added";
    } else if (t.type === "signup_bonus") {
      note = "Signup bonus";
    } else if (t.type === "refund") {
      note = t.description ?? "Refund";
    }
    return {
      id: t.id,
      amount: t.amount,
      type: isCredit ? "credit" : "debit",
      note,
      status,
      createdAt: t.createdAt,
    };
  });

  const pendingWithdrawals = withdrawals
    .filter((w) => w.status === "pending")
    .map((w) => ({
      id: w.id,
      amount: -w.amount,
      type: "debit" as const,
      note: "Withdraw",
      status: "pending" as const,
      createdAt: w.createdAt,
    }));

  const pendingDeposits = depositReqs
    .filter((d) => d.status === "pending")
    .map((d) => ({
      id: d.id,
      amount: d.amount,
      type: "credit" as const,
      note: "Deposit",
      status: "pending" as const,
      createdAt: d.createdAt,
    }));

  const merged = [...txItems, ...pendingWithdrawals, ...pendingDeposits].sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
  return NextResponse.json(merged);
}
