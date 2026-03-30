import { type ReactNode } from "react";

interface SectionProps {
  id?: string;
  children: ReactNode;
  className?: string;
  background?: "base" | "card" | "elevated";
}

export function Section({
  id,
  children,
  className = "",
  background = "card",
}: SectionProps) {
  const bgClass =
    background === "base"
      ? "bg-base"
      : background === "elevated"
        ? "bg-elevated"
        : "bg-card";

  return (
    <section
      id={id}
      className={`relative py-16 px-4 sm:px-6 lg:px-8 ${bgClass} ${className}`}
    >
      <div className="mx-auto max-w-6xl">{children}</div>
    </section>
  );
}
