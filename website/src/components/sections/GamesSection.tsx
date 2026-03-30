"use client";

import { useState, useRef, useCallback, useEffect } from "react";
import Image from "next/image";
import { brand } from "@config/brand";
import { Section } from "@/components/ui";

const IMAGE_EXTS = [".jpg", ".jpeg", ".png", ".webp"];

type CarouselGame = {
  key: string;
  name: string;
  /** From Supabase / admin — full URL or site path */
  imageUrl: string | null;
  /** Static brand games — base path without extension */
  legacyBase?: string;
};

async function fetchGames(): Promise<{ id: string; name: string; imageUrl: string | null }[]> {
  const res = await fetch(`/api/games?_cb=${Date.now()}`, { credentials: "include", cache: "no-store" });
  const data = await res.json().catch(() => []);
  if (!res.ok || !Array.isArray(data)) return [];
  return data;
}

function GameCard({ game }: { game: CarouselGame }) {
  const [imgError, setImgError] = useState(false);
  const [srcIndex, setSrcIndex] = useState(0);
  const directSrc = game.imageUrl?.trim() || null;
  const basePath = game.legacyBase;
  const src =
    !directSrc && basePath ? basePath + IMAGE_EXTS[srcIndex] : directSrc ?? "";

  return (
    <div
      className="relative flex min-w-full shrink-0 items-center justify-center px-2 py-4 sm:min-w-[50%] sm:px-3 lg:min-w-[33.333%]"
      style={{
        scrollSnapAlign: "start",
        scrollSnapStop: "always",
      }}
    >
      <div
        className="relative aspect-[3/4] w-full max-w-full overflow-hidden"
        style={{
          borderRadius: "12%",
          boxShadow:
            "0 8px 24px rgba(0,0,0,0.2), 0 4px 12px rgba(0,0,0,0.15)",
        }}
      >
        {!imgError && (directSrc || basePath) ? (
          <Image
            src={src}
            alt={game.name}
            fill
            className="object-cover"
            sizes="(max-width: 640px) 100vw, 384px"
            unoptimized
            onError={() => {
              if (directSrc) {
                setImgError(true);
              } else if (srcIndex < IMAGE_EXTS.length - 1) {
                setSrcIndex((i) => i + 1);
              } else {
                setImgError(true);
              }
            }}
          />
        ) : (
          <div className="absolute inset-0 flex items-center justify-center bg-gradient-to-br from-stone-700 to-stone-900">
            <span className="text-lg font-bold text-white">{game.name}</span>
          </div>
        )}
        <div
          className="absolute bottom-0 left-0 right-0 flex items-center justify-center bg-gradient-to-t from-black/80 to-transparent p-4"
          style={{ borderRadius: "0 0 12% 12%" }}
        >
          <span className="text-xl font-bold text-white sm:text-2xl">
            {game.name}
          </span>
        </div>
      </div>
    </div>
  );
}

function getCardsPerView(width: number): number {
  if (width >= 1024) return 3;
  if (width >= 640) return 2;
  return 1;
}

type BrandCarouselEntry = { name: string; slug: string; image?: string };

function brandGamesToCarousel(): CarouselGame[] {
  const entries = brand.games as readonly BrandCarouselEntry[];
  return entries.map((g) => ({
    key: g.slug,
    name: g.name,
    imageUrl: null,
    legacyBase: g.image ?? `/images/games/${g.slug}`,
  }));
}

function mapApiGamesToCarousel(
  apiGames: { id: string; name: string; imageUrl: string | null }[],
): CarouselGame[] {
  return apiGames.map((g) => ({
    key: g.id,
    name: g.name,
    imageUrl: g.imageUrl,
  }));
}

export type GamesSectionProps = {
  /** From server render — avoids stale client /api/games cache overwriting fresh data */
  serverGames?: { id: string; name: string; imageUrl: string | null }[];
};

export function GamesSection({ serverGames }: GamesSectionProps = {}) {
  const [games, setGames] = useState<CarouselGame[]>(() =>
    serverGames && serverGames.length > 0 ? mapApiGamesToCarousel(serverGames) : brandGamesToCarousel(),
  );
  const scrollRef = useRef<HTMLDivElement>(null);
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    if (serverGames && serverGames.length > 0) return;
    fetchGames()
      .then((apiGames) => {
        if (apiGames.length > 0) {
          setGames(mapApiGamesToCarousel(apiGames));
        }
      })
      .catch(() => {});
  }, [serverGames]);

  const updateActiveIndex = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    const scrollLeft = el.scrollLeft;
    const containerWidth = el.offsetWidth;
    const cardsPerView = getCardsPerView(containerWidth);
    const cardWidth = containerWidth / cardsPerView;
    const index = Math.round(scrollLeft / cardWidth);
    const max = Math.max(0, games.length - 1);
    setActiveIndex(Math.min(Math.max(0, index), max));
  }, [games.length]);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    updateActiveIndex();
    el.addEventListener("scroll", updateActiveIndex);
    window.addEventListener("resize", updateActiveIndex);
    return () => {
      el.removeEventListener("scroll", updateActiveIndex);
      window.removeEventListener("resize", updateActiveIndex);
    };
  }, [updateActiveIndex]);

  const scrollTo = (index: number) => {
    const el = scrollRef.current;
    if (!el) return;
    const containerWidth = el.offsetWidth;
    const cardsPerView = getCardsPerView(containerWidth);
    const cardWidth = containerWidth / cardsPerView;
    el.scrollTo({ left: index * cardWidth, behavior: "smooth" });
  };

  return (
    <Section id="games" background="card" className="pb-8">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-text sm:text-3xl">Games</h2>
      </div>
      <div className="mt-8 w-full pb-8">
        <div
          ref={scrollRef}
          className="flex overflow-x-auto scroll-smooth"
          style={{
            scrollSnapType: "x mandatory",
            WebkitOverflowScrolling: "touch",
          }}
        >
          {games.map((game) => (
            <GameCard key={game.key} game={game} />
          ))}
        </div>
        <div className="mt-6 flex justify-center gap-2.5 px-4">
          {games.map((_, index) => (
            <button
              key={index}
              onClick={() => scrollTo(index)}
              className={`h-2.5 w-2.5 rounded-full transition-all focus:outline-none focus:ring-2 focus:ring-orange focus:ring-offset-2 ${
                index === activeIndex
                  ? "scale-125 bg-orange"
                  : "bg-gray-300 hover:bg-gray-400"
              }`}
              aria-label={`Go to slide ${index + 1}`}
            />
          ))}
        </div>
      </div>
    </Section>
  );
}
