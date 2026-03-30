"use client";

import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import { LoadingSpinner } from "@/components/ui";

export function AdminGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (pathname === "/admin/login") {
      setLoading(false);
      return;
    }
    fetch("/api/admin/session")
      .then((res) => res.json())
      .then((data) => {
        if (!data.admin) {
          router.replace("/admin/login");
        }
      })
      .finally(() => setLoading(false));
  }, [pathname, router]);

  if (pathname === "/admin/login") {
    return <>{children}</>;
  }

  if (loading) {
    return (
      <div className="admin-page flex min-h-screen items-center justify-center">
        <LoadingSpinner size="lg" fullScreen label="Loading..." />
      </div>
    );
  }

  return <>{children}</>;
}
