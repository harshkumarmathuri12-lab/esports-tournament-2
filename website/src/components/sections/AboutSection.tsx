import { brand } from "@config/brand";
import { Section } from "@/components/ui";

export function AboutSection() {
  const about = brand.about;

  return (
    <Section id="about" background="base">
      <div className="mx-auto max-w-3xl text-center">
        <h2 className="text-2xl font-bold text-text sm:text-3xl">
          {about.title}
        </h2>
        <div className="mt-6 space-y-4 text-text-muted">
          <p>{about.paragraph1}</p>
          <p>{about.paragraph2}</p>
        </div>
        <ul className="mt-8 grid gap-3 text-left sm:grid-cols-2">
          {about.features.map((feature, i) => (
            <li
              key={i}
              className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-3"
            >
              <span className="text-accent">✓</span>
              <span className="text-text">{feature}</span>
            </li>
          ))}
        </ul>
      </div>
    </Section>
  );
}
