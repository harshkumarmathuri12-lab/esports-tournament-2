import { createHmac } from "node:crypto";

import bcrypt from "bcryptjs";
import { NextResponse } from "next/server";

import { adminStore } from "@/lib/admin-store";
import { getSupabase } from "@/lib/supabase";

const JWT_EXPIRY_SECONDS = 60 * 60 * 24 * 7;

type JwtPayload = {
  sub: string;
  email: string;
  adminname: string;
  isMasterAdmin: boolean;
  usersAccess: boolean;
  coinsAccess: boolean;
  gamesAccessType: "all" | "specific";
  allowedGameIds: string[];
  iat: number;
  exp: number;
};

function base64UrlEncode(value: string) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signJwt(payload: JwtPayload, secret: string) {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const content = `${encodedHeader}.${encodedPayload}`;
  const signature = createHmac("sha256", secret)
    .update(content)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  return `${content}.${signature}`;
}

export async function POST(request: Request) {
  const { email, password } = await request.json();

  if (!email || !password || typeof email !== "string" || typeof password !== "string") {
    return NextResponse.json({ error: "Email and password required" }, { status: 400 });
  }

  const jwtSecret = process.env.ADMIN_JWT_SECRET ?? process.env.APP_SESSION_SECRET;
  if (!jwtSecret) {
    return NextResponse.json({ error: "Server misconfigured" }, { status: 500 });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const supabase = getSupabase();

  if (supabase) {
    const { data: linkedUser } = await supabase
      .from("users")
      .select("id, email")
      .ilike("email", normalizedEmail)
      .maybeSingle();

    let adminRow:
      | {
          id: string;
          adminname: string;
          password_hash: string;
          is_master_admin?: boolean;
          users_access?: boolean;
          coins_access?: boolean;
          games_access_type?: "all" | "specific";
          created_at?: string;
        }
      | null = null;

    if (linkedUser?.id) {
      const { data } = await supabase
        .from("admins")
        .select("id, adminname, password_hash, is_master_admin, users_access, coins_access, games_access_type, created_at")
        .eq("user_id", linkedUser.id)
        .maybeSingle();
      adminRow = data;
    }

    if (!adminRow) {
      const { data } = await supabase
        .from("admins")
        .select("id, adminname, password_hash, is_master_admin, users_access, coins_access, games_access_type, created_at")
        .ilike("adminname", normalizedEmail)
        .maybeSingle();
      adminRow = data;
    }

    if (!adminRow?.password_hash) {
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
    }

    const passwordOk = await bcrypt.compare(password, adminRow.password_hash);
    if (!passwordOk) {
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
    }

    const { data: allowedGames } = await supabase
      .from("admin_allowed_games")
      .select("game_id")
      .eq("admin_id", adminRow.id);

    const now = Math.floor(Date.now() / 1000);
    const token = signJwt(
      {
        sub: adminRow.id,
        email: linkedUser?.email ?? normalizedEmail,
        adminname: adminRow.adminname,
        isMasterAdmin: adminRow.is_master_admin ?? false,
        usersAccess: adminRow.users_access ?? false,
        coinsAccess: adminRow.coins_access ?? false,
        gamesAccessType: adminRow.games_access_type ?? "all",
        allowedGameIds: (allowedGames ?? []).map((row) => row.game_id),
        iat: now,
        exp: now + JWT_EXPIRY_SECONDS,
      },
      jwtSecret
    );

    return NextResponse.json({
      token,
      admin: {
        id: adminRow.id,
        email: linkedUser?.email ?? normalizedEmail,
        adminname: adminRow.adminname,
        isMasterAdmin: adminRow.is_master_admin ?? false,
        usersAccess: adminRow.users_access ?? false,
        coinsAccess: adminRow.coins_access ?? false,
        gamesAccessType: adminRow.games_access_type ?? "all",
        allowedGameIds: (allowedGames ?? []).map((row) => row.game_id),
      },
    });
  }

  const admins = adminStore.getAllAdmins();
  const admin = admins.find((item) => item.adminname.toLowerCase() === normalizedEmail);
  if (!admin) {
    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
  }

  const authenticatedAdmin = await adminStore.login(admin.adminname, password);
  if (!authenticatedAdmin) {
    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
  }

  const now = Math.floor(Date.now() / 1000);
  const token = signJwt(
    {
      sub: authenticatedAdmin.id,
      email: normalizedEmail,
      adminname: authenticatedAdmin.adminname,
      isMasterAdmin: authenticatedAdmin.isMasterAdmin,
      usersAccess: authenticatedAdmin.usersAccess,
      coinsAccess: authenticatedAdmin.coinsAccess,
      gamesAccessType: authenticatedAdmin.gamesAccessType,
      allowedGameIds: authenticatedAdmin.allowedGameIds,
      iat: now,
      exp: now + JWT_EXPIRY_SECONDS,
    },
    jwtSecret
  );

  return NextResponse.json({
    token,
    admin: {
      id: authenticatedAdmin.id,
      email: normalizedEmail,
      adminname: authenticatedAdmin.adminname,
      isMasterAdmin: authenticatedAdmin.isMasterAdmin,
      usersAccess: authenticatedAdmin.usersAccess,
      coinsAccess: authenticatedAdmin.coinsAccess,
      gamesAccessType: authenticatedAdmin.gamesAccessType,
      allowedGameIds: authenticatedAdmin.allowedGameIds,
    },
  });
}
