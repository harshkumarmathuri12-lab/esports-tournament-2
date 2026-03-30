import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { getAppUserId } from "@/lib/app-auth";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const userId = await getAppUserId();
    if (!userId) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

    const { id: matchId } = await params;
    const body = await request.json();
    const { inGameName, inGameUid, teamMembers } = body;
    if (!inGameName || !inGameUid) {
      return NextResponse.json(
        { error: "inGameName and inGameUid required" },
        { status: 400 }
      );
    }
    const store = getStore();
    const result = await store.joinMatch(
      matchId,
      userId,
      String(inGameName).trim(),
      String(inGameUid).trim(),
      Array.isArray(teamMembers)
        ? teamMembers.slice(0, 3).map((t: { inGameName?: string; inGameUid?: string }) => ({
            inGameName: String(t?.inGameName ?? "").trim(),
            inGameUid: String(t?.inGameUid ?? "").trim(),
          }))
        : undefined
    );
    if (result?.error) {
      return NextResponse.json({ error: result.error }, { status: 400 });
    }
    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
}
