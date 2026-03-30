import Link from "next/link";
import { brand } from "@config/brand";
import { Section } from "@/components/ui";

export function GetAppSection() {
  const getApp = brand.getApp;
  const playUrl = "/play";
  const description = brand.whyDownload?.description?.replace(
    "{appName}",
    brand.appName
  );

  return (
    <Section id="download" background="card">
      <div className="mx-auto max-w-2xl text-center font-ultimatum">
        <h2 className="text-2xl font-bold text-text sm:text-3xl">
          Ready to play?
        </h2>
        <p className="mt-4 text-text-muted">
          Play in your browser — sign up, join tournaments, manage coins, and more. No app download required.
        </p>
        {description && (
          <p className="mt-2 text-sm text-text-dim">{description}</p>
        )}
        <ul className="mt-8 space-y-2 text-left text-text-muted">
          {getApp?.features?.map((feature, i) => (
            <li key={i} className="flex items-start gap-2">
              <span className="mt-0.5 text-accent">•</span>
              <span>{feature}</span>
            </li>
          ))}
        </ul>
        <Link
          href={playUrl}
          className="mt-8 inline-block rounded-lg px-8 py-4 text-base font-bold uppercase tracking-wider text-stone-900 transition hover:opacity-95 active:scale-[0.98]"
          style={{
            background: "linear-gradient(to right, #FFC107, #FFA000)",
            boxShadow: "0 4px 14px rgba(255, 160, 0, 0.4)",
          }}
        >
          Play
        </Link>
        <p className="mt-4 text-sm text-text-dim">
          Play in your browser — no download required
        </p>
      </div>
    </Section>
  );
}
