import { NextResponse } from "next/server";
import { getStore } from "@/lib/store";
import { createAppSessionCookie } from "@/lib/app-auth";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { email, password } = body;
    if (!email || typeof email !== "string") {
      return NextResponse.json({ error: "Email required" }, { status: 400 });
    }
    if (!password || typeof password !== "string") {
      return NextResponse.json({ error: "Password required" }, { status: 400 });
    }
    const user = await getStore().signInUser(email.trim(), password);
    if (!user) {
      return NextResponse.json({ error: "Invalid email or password" }, { status: 401 });
    }
    const { name, value, options } = createAppSessionCookie(user.id);
    const res = NextResponse.json({ user });
    res.cookies.set(name, value, options);
    return res;
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
}
