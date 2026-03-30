/**
 * =============================================================================
 * TEMPLATE CUSTOMIZATION - Edit this single file to customize your app
 * =============================================================================
 *
 * CUSTOMIZABLE ITEMS:
 * - appName ............. Navbar, footer, play pages header
 * - social.instagram .... Instagram link (navbar, footer). Set "" to hide.
 * - social.youtube ...... YouTube link (navbar, footer). Set "" to hide.
 * - images.homepageBackground ... Hero section background image path
 * - hero.titleAccent .... Hero top line (e.g. "THE BEST")
 * - hero.titleMain ...... Hero main title (e.g. "ESPORTS APP")
 * - hero.subtitle ....... Hero tagline
 * - tagline ............. Short tagline (footer, meta)
 * - meta.title .......... Page title. Use {appName} and {tagline} as placeholders.
 * - meta.description .... Page description for SEO
 * - footer.links ........ Footer legal links
 *
 * =============================================================================
 */

export const brand = {
  /** App name - used in navbar, footer, and all /play pages */
  appName: "eSports Turnaments",

  /** Social links - shown in navbar and footer. Set to "" to hide. */
  social: {
    instagram: "https://instagram.com",
    youtube: "https://youtube.com",
  },

  /** Image paths - place files in website/public/images/ */
  images: {
    /** Hero section background - e.g. "/images/home-page-bg.jpg" */
    homepageBackground: "/images/home-page-bg.jpg",
  },

  /** Short tagline - used in footer and meta */
  tagline: "Compete. Connect. Conquer.",

  /** Hero section - the main landing banner */
  hero: {
    /** Top line (smaller text) - e.g. "THE BEST" */
    titleAccent: "THE BEST",
    /** Main title (large text) - e.g. "ESPORTS APP" */
    titleMain: "ESPORTS APP",
    subtitle: "Compete. Connect. Conquer.",
  },

  /** About section (if used) */
  about: {
    title: "About the App",
    paragraph1:
      "Esports App is your all-in-one hub for competitive gaming. Whether you're a casual player looking to join local tournaments or a seasoned pro tracking your climb through the ranks, we've got you covered.",
    paragraph2:
      "Discover upcoming tournaments across your favorite games, get real-time match updates, connect with teammates and rivals, and showcase your achievements. Our platform brings the entire esports ecosystem together in one place—so you can focus on what matters most: the game.",
    features: [
      "Tournament discovery and registration",
      "Live match tracking and notifications",
      "Community features and team building",
      "Player profiles and stats",
    ],
  },

  /** Games - shown in games carousel */
  games: [
    { name: "BGMI", slug: "bgmi", image: "/images/bgmi_image" },
    { name: "Free Fire", slug: "free-fire", image: "/images/freefire_image" },
    { name: "COD", slug: "cod", image: "/images/cod_image" },
  ],

  /** Stats section */
  stats: {
    title: "Constantly Growing",
    subtitle: "Providing the best Esports experience to millions of aspiring gamers.",
    items: [
      { value: "6.1M+", label: "Total Gamers" },
      { value: "120K+", label: "Matches Played" },
      { value: "10M+", label: "Leagues Joined" },
      { value: "100M+", label: "Winning Distributed" },
    ],
  },

  /** Why Download section */
  whyDownload: {
    title: "Why Download",
    description:
      "{appName} has been made for gamers to start and build their journey as a gamer and eventually become pro Esports athletes!",
  },

  /** Get App section */
  getApp: {
    title: "Get App now",
    subtitle: "Download our Android & iOS App for ease to use",
    features: [
      "Build your profile with cool avatars and stats from each tournament.",
      "Link your account with your college to participate in college leagues.",
      "Find all your Esports content at one place!",
      "Earn coins to win exciting rewards & merchandises",
    ],
    buttonLabel: "Download App",
    url: "#",
    platforms: "Available for iOS and Android",
  },

  /** Download CTA section (legacy) */
  download: {
    ctaTitle: "Ready to join the arena?",
    ctaSubtitle: "Download the Esports App and start your competitive journey today.",
    buttonLabel: "Download App",
    url: "#",
    platforms: "Available for iOS and Android",
  },

  /** Footer */
  footer: {
    links: [
      { label: "About", href: "#" },
      { label: "Terms & Conditions", href: "#" },
      { label: "Privacy Policy", href: "#" },
      { label: "Blogs", href: "#" },
    ],
    copyright: "All Rights Reserved.",
  },

  /** SEO / Meta - use {appName} and {tagline} as placeholders */
  meta: {
    title: "{appName} - {tagline}",
    description:
      "The ultimate platform for esports enthusiasts to discover tournaments, track matches, and connect with the gaming community.",
  },

  /** Primary brand color (hex) */
  colors: {
    primary: "#e63946",
    primaryHover: "#c1121f",
  },
} as const;

export type BrandConfig = typeof brand;

/** Helper to resolve meta strings with placeholders */
export function resolveMeta(str: string): string {
  return str
    .replace(/\{appName\}/g, brand.appName)
    .replace(/\{tagline\}/g, brand.tagline);
}
