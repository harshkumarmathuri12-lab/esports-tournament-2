export default function PlayLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <div className="min-h-screen bg-[#0c0c0e] text-[#F8FAFC]">
      {children}
    </div>
  );
}
