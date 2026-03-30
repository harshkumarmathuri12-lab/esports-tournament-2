import "./admin.css";
import { AdminGuard } from "@/components/admin/AdminGuard";

export default function AdminLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <AdminGuard>
      <div className="admin-page">
        <div className="relative z-10">{children}</div>
      </div>
    </AdminGuard>
  );
}
