"use client";

import { useState } from "react";
import Image from "next/image";
import Link from "next/link";
import { brand } from "@config/brand";

const VIGNETTE_BOTTOM =
  "linear-gradient(to top, rgba(0,0,0,1) 0%, rgba(0,0,0,1) 15%, rgba(0,0,0,0.3) 37.5%, transparent 60%)";
const VIGNETTE_LEFT =
  "linear-gradient(to right, rgba(0,0,0,1) 0%, rgba(0,0,0,1) 10%, rgba(0,0,0,0.3) 35%, transparent 60%)";

export function HeroSection() {
  const playUrl = "/play";
  const hero = brand.hero;

  const [imgError, setImgError] = useState(false);
  const bgSrc = brand.images?.homepageBackground ?? "/images/home-page-bg.jpg";

  return (
    <section className="relative flex min-h-screen items-end overflow-hidden md:items-center">
      <div className="absolute inset-0">
        {!imgError ? (
          <Image
            src={bgSrc}
            alt=""
            fill
            className="object-cover"
            priority
            quality={90}
            sizes="(max-width: 768px) 750px, 100vw"
            onError={() => setImgError(true)}
          />
        ) : (
          <div
            className="absolute inset-0 bg-gradient-to-br from-stone-800 via-stone-900 to-black"
            aria-hidden
          />
        )}
        <div
          className="pointer-events-none absolute inset-0 z-[1] md:hidden"
          style={{ background: VIGNETTE_BOTTOM }}
          aria-hidden
        />
        <div
          className="pointer-events-none absolute inset-0 z-[1] hidden md:block"
          style={{ background: VIGNETTE_LEFT }}
          aria-hidden
        />
      </div>

      <div className="hero-cta-container relative z-[2] mx-auto flex min-h-[45vh] w-full max-w-[min(100%,28rem)] flex-col justify-between px-6 pb-6 pt-8 text-center md:min-h-[38vh] md:pb-6 md:pt-8">
        <div>
          <h1 className="mb-6 w-full font-ultimatum tracking-wide text-white drop-shadow-lg">
            <span
              className="block w-full leading-none"
              style={{ fontSize: "clamp(0.875rem, 12cqw, 3rem)" }}
            >
              {hero?.titleAccent ?? "THE BEST"}
            </span>
            <span
              className="mt-1 block w-full whitespace-nowrap leading-none"
              style={{ fontSize: "clamp(1rem, 16.5cqw, 4rem)" }}
            >
              {hero?.titleMain ?? "ESPORTS APP"}
            </span>
          </h1>
          <div className="mt-4 flex items-center justify-center gap-6 sm:gap-8 font-ultimatum">
            <div className="text-center">
              <div
                className="text-xl font-bold text-accent sm:text-2xl"
                style={{ textShadow: "0 2px 8px rgba(0,0,0,0.6)" }}
              >
                10,000+
              </div>
              <div
                className="mt-1 text-sm font-medium text-white/80"
                style={{ textShadow: "0 1px 4px rgba(0,0,0,0.5)" }}
              >
                Players
              </div>
            </div>
            <div className="h-10 w-px shrink-0 bg-white/50" aria-hidden />
            <div className="text-center">
              <div
                className="text-xl font-bold text-accent sm:text-2xl"
                style={{ textShadow: "0 2px 8px rgba(0,0,0,0.6)" }}
              >
                1,000+
              </div>
              <div
                className="mt-1 text-sm font-medium text-white/80"
                style={{ textShadow: "0 1px 4px rgba(0,0,0,0.5)" }}
              >
                Matches Hosted
              </div>
            </div>
          </div>
        </div>
        <Link
          href={playUrl}
          className="mt-auto block w-full rounded-lg py-4 text-center text-base font-bold uppercase tracking-wider text-stone-900 transition hover:opacity-95 active:scale-[0.98] font-ultimatum"
          style={{
            background: "linear-gradient(to right, #FFC107, #FFA000)",
            boxShadow: "0 4px 14px rgba(255, 160, 0, 0.4)",
          }}
        >
          PLAY
        </Link>
      </div>
    </section>
  );
}
