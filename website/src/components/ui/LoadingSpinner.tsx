"use client";

/**
 * Themed loading spinner for data fetching states.
 * Matches the esports app dark theme with orange accent.
 */

type LoadingSpinnerProps = {
  /** Size: "sm" | "md" | "lg" */
  size?: "sm" | "md" | "lg";
  /** Optional label below the spinner */
  label?: string;
  /** Use full viewport height (for page-level loading) */
  fullScreen?: boolean;
  /** Use compact padding (for inline/section loading) */
  compact?: boolean;
};

const sizeMap = { sm: 24, md: 40, lg: 56 };

export function LoadingSpinner({
  size = "md",
  label,
  fullScreen = false,
  compact = false,
}: LoadingSpinnerProps) {
  const px = sizeMap[size];
  return (
    <div
      className={`flex flex-col items-center justify-center gap-4 ${
        fullScreen ? "min-h-screen" : compact ? "py-8" : "py-16"
      }`}
    >
      <div className="relative" style={{ width: px, height: px }}>
        {/* Subtle outer ring */}
        <div className="absolute inset-0 rounded-full border-2 border-[#f97316]/20" />
        {/* Main spinner */}
        <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-[#f97316] animate-spin" />
      </div>
      {label && (
        <p className="text-sm text-[#94A3B8] animate-pulse">
          {label}
        </p>
      )}
    </div>
  );
}
