import Link from "next/link";
import { brand } from "@config/brand";
import { getPlatformRef } from "@/lib/platform-ref";

export function Footer() {
  return (
    <footer className="relative z-10 overflow-hidden bg-[#0c0c0e]">
      {/* Top accent line */}
      <div
        className="h-1 w-full"
        style={{
          background: "linear-gradient(90deg, transparent, #f97316 20%, #f97316 80%, transparent)",
          opacity: 0.9,
        }}
      />
      <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
          {/* Brand column */}
          <div className="sm:col-span-2 lg:col-span-1">
            <Link href="/" className="inline-block">
              <span className="font-ultimatum text-xl font-bold tracking-tight text-white">
                {brand.appName}
              </span>
            </Link>
            <p className="mt-2 text-sm text-stone-400">
              {brand.tagline}
            </p>
            {/* Social links */}
            <div className="mt-4 flex gap-3">
              {brand.social.instagram && (
                <a
                  href={brand.social.instagram}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/5 text-stone-400 transition hover:bg-orange-500/20 hover:text-orange-400"
                  aria-label="Instagram"
                >
                  <svg className="h-5 w-5" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073z" />
                  </svg>
                </a>
              )}
              {brand.social.youtube && (
                <a
                  href={brand.social.youtube}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/5 text-stone-400 transition hover:bg-orange-500/20 hover:text-orange-400"
                  aria-label="YouTube"
                >
                  <svg className="h-5 w-5" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z" />
                  </svg>
                </a>
              )}
            </div>
          </div>

          {/* Quick links */}
          <div>
            <h3 className="font-ultimatum text-sm font-semibold uppercase tracking-wider text-stone-500">
              Quick Links
            </h3>
            <ul className="mt-4 space-y-2">
              <li>
                <Link href="#games" className="text-sm text-stone-400 transition hover:text-orange-400">
                  Games
                </Link>
              </li>
              <li>
                <Link href="#faq" className="text-sm text-stone-400 transition hover:text-orange-400">
                  FAQ
                </Link>
              </li>
              <li>
                <Link href="/play" className="text-sm text-stone-400 transition hover:text-orange-400">
                  Play Now
                </Link>
              </li>
            </ul>
          </div>

          {/* Legal */}
          <div>
            <h3 className="font-ultimatum text-sm font-semibold uppercase tracking-wider text-stone-500">
              Legal
            </h3>
            <ul className="mt-4 space-y-2">
              {brand.footer.links.map((link) => (
                <li key={link.label}>
                  <Link
                    href={link.href}
                    className="text-sm text-stone-400 transition hover:text-orange-400"
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="mt-12 flex flex-col items-center justify-between gap-4 border-t border-white/10 pt-8 sm:flex-row">
          <p className="text-center text-sm text-stone-500 sm:text-left">
            © {new Date().getFullYear()} {brand.appName}. {brand.footer.copyright}
          </p>
          {(() => {
            const ref = getPlatformRef();
            if (!ref.url || !ref.label) return null;
            return (
              <a
                href={ref.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 transition hover:opacity-80"
              >
                <span className="text-xs text-stone-600">{ref.prefix}</span>
                <span className="font-ultimatum text-sm font-bold text-orange-500/80">{ref.label}</span>
              </a>
            );
          })()}
        </div>
      </div>
    </footer>
  );
}
