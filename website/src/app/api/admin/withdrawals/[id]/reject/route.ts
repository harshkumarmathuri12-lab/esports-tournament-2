import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAdminSession } from "@/lib/admin-auth";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const admin = await getAdminSession();
  if (!admin) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!admin.coinsAccess) return NextResponse.json({ error: "No coins access" }, { status: 403 });
  const { id } = await params;
  const body = await request.json().catch(() => ({}));
  const note = typeof body.note === "string" ? body.note.trim() : "";
  if (!note) return NextResponse.json({ error: "Rejection note is required" }, { status: 400 });
  const req = await getStore().rejectWithdrawalRequest(id, note);
  if (!req) return NextResponse.json({ error: "Request not found or already processed" }, { status: 404 });
  return NextResponse.json(req);
}
