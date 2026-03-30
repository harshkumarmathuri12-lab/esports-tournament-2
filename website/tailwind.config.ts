import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/styles/**/*.css",
  ],
  theme: {
    extend: {
      fontFamily: {
        ultimatum: ["var(--font-ultimatum)"],
      },
      colors: {
        bg: {
          base: "var(--bg-base)",
          card: "var(--bg-card)",
          elevated: "var(--bg-elevated)",
        },
        border: {
          DEFAULT: "var(--border)",
          hover: "var(--border-hover)",
        },
        accent: {
          DEFAULT: "var(--accent)",
          muted: "var(--accent-muted)",
        },
        yellow: {
          DEFAULT: "var(--yellow)",
          muted: "var(--yellow-muted)",
        },
        orange: {
          DEFAULT: "var(--orange)",
          muted: "var(--orange-muted)",
        },
        text: {
          DEFAULT: "var(--text)",
          muted: "var(--text-muted)",
          dim: "var(--text-dim)",
        },
      },
      boxShadow: {
        accent: "0 0 20px var(--accent-glow)",
      },
    },
  },
  plugins: [],
};

export default config;
