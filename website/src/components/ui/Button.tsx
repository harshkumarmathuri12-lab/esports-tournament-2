import Link from "next/link";
import { type ReactNode } from "react";

type ButtonVariant = "primary" | "secondary" | "ghost" | "outline";

interface ButtonProps {
  children: ReactNode;
  href?: string;
  variant?: ButtonVariant;
  className?: string;
  disabled?: boolean;
  type?: "button" | "submit";
  onClick?: () => void;
}

const variantStyles: Record<ButtonVariant, string> = {
  primary:
    "bg-gradient-to-r from-yellow to-orange text-stone-900 font-bold shadow-lg shadow-orange/30 hover:opacity-95 active:scale-[0.98]",
  secondary: "bg-bg-elevated text-text border border-border hover:border-border-hover",
  ghost: "text-text hover:bg-bg-elevated",
  outline: "border-2 border-accent text-accent hover:bg-accent hover:text-white",
};

export function Button({
  children,
  href,
  variant = "primary",
  className = "",
  disabled,
  type = "button",
  onClick,
}: ButtonProps) {
  const base =
    "inline-flex items-center justify-center rounded-lg px-6 py-3 text-base font-medium transition focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed";

  const styles = `${base} ${variantStyles[variant]} ${className}`;

  if (href) {
    return (
      <Link href={href} className={styles}>
        {children}
      </Link>
    );
  }

  return (
    <button type={type} className={styles} disabled={disabled} onClick={onClick}>
      {children}
    </button>
  );
}
