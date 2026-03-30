import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { createAppSessionCookie } from "@/lib/app-auth";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { email, displayName, password } = body;
    if (!email || typeof email !== "string") {
      return NextResponse.json({ error: "Email required" }, { status: 400 });
    }
    if (!password || typeof password !== "string" || password.length < 6) {
      return NextResponse.json({ error: "Password required (min 6 characters)" }, { status: 400 });
    }
    const name = typeof displayName === "string" && displayName.trim()
      ? displayName.trim()
      : email.substring(0, email.indexOf("@")) || "User";
    const user = await getStore().addUser(email.trim(), name, password);
    if (!user) {
      return NextResponse.json({ error: "Email already registered" }, { status: 409 });
    }
    const { name: cookieName, value, options } = createAppSessionCookie(user.id);
    const res = NextResponse.json({ user });
    res.cookies.set(cookieName, value, options);
    return res;
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
}
