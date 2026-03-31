import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { NextResponse } from "next/server";

const TEMP_ADMIN = {
  id: "temp-admin-1",
  email: "admin@example.com",
  // Password: admin123
  passwordHash: "$2b$10$ZEYPIVjXGH2XX4A61Xfr/e88estLxv4mz5ACbj3DzToKAm5t1b2cW",
};

export async function POST(request: Request) {
  const { email, password } = await request.json();

  if (!email || !password || typeof email !== "string" || typeof password !== "string") {
    return NextResponse.json({ error: "Email and password required" }, { status: 400 });
  }

  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    return NextResponse.json({ error: "Server misconfigured" }, { status: 500 });
  }

  const normalizedEmail = email.trim().toLowerCase();
  if (normalizedEmail !== TEMP_ADMIN.email) {
    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
  }

  const passwordMatches = await bcrypt.compare(password, TEMP_ADMIN.passwordHash);
  if (!passwordMatches) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const token = jwt.sign(
    {
      sub: TEMP_ADMIN.id,
      email: TEMP_ADMIN.email,
      role: "admin",
    },
    jwtSecret,
    { expiresIn: "7d" }
  );

  return NextResponse.json({
    token,
  });
}
