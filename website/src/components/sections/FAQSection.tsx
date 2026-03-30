"use client";

import { useState } from "react";
import { Section } from "@/components/ui";

const FAQ_ITEMS = [
  {
    question: "How do I join a tournament?",
    answer: [
      "Click on the Play button in the home page and then Open the Tournaments section, select an available tournament, and tap Join.",
      "Ensure you meet the entry requirements before registering.",
    ],
  },
  {
    question: "Is the app free to use?",
    answer: [
      "Yes. The app is free to download and use.",
      "Some tournaments may charge an entry fee depending on the prize pool.",
    ],
  },
  {
    question: "How are winners decided?",
    answer: [
      "Winners are decided by official game results and tournament rules.",
      "Scores and placements are verified before any rewards are distributed.",
    ],
  },
  {
    question: "When do I receive my rewards?",
    answer: [
      "Rewards are typically processed shortly after tournament results are verified.",
      "Processing time may vary based on the tournament type.",
    ],
  },
  {
    question: "What if a hacker killed me in the match?",
    answer: [
      "Contact customer support and report the player in the app with supporting evidence (e.g., screenshots or video clips).",
      "We will investigate and take appropriate action after verification. If your report is valid, your entry fee will be refunded.",
    ],
  },
];

export function FAQSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  return (
    <Section id="faq" background="elevated" className="pt-8">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-text sm:text-3xl">FAQ</h2>
        <p className="mt-4 text-text-muted">Frequently asked questions</p>
      </div>
      <div className="mx-auto mt-8 max-w-3xl space-y-3">
        {FAQ_ITEMS.map((item, index) => (
          <div
            key={index}
            className="overflow-hidden rounded-xl border border-border bg-base"
          >
            <button
              onClick={() => setOpenIndex(openIndex === index ? null : index)}
              className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left transition hover:bg-elevated/50"
            >
              <span className="font-medium text-text">{item.question}</span>
              <span
                className={`shrink-0 text-xl font-light text-text transition-transform duration-200 ${
                  openIndex === index ? "rotate-45" : ""
                }`}
              >
                +
              </span>
            </button>
            <div
              className={`grid transition-all duration-200 ease-in-out ${
                openIndex === index ? "grid-rows-[1fr]" : "grid-rows-[0fr]"
              }`}
            >
              <div className="overflow-hidden">
                <div className="border-t border-border px-5 py-4">
                  <div className="space-y-2 text-text-muted">
                    {item.answer.map((paragraph, i) => (
                      <p key={i}>{paragraph}</p>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </Section>
  );
}
