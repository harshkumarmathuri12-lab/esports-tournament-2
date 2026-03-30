import { brand } from "@config/brand";
import { Section } from "@/components/ui";

export function StatsSection() {
  const stats = brand.stats;

  return (
    <Section background="elevated">
      <div className="text-center font-ultimatum">
        <h2 className="text-2xl font-bold text-text sm:text-3xl">
          {stats.title}
        </h2>
        <p className="mt-2 text-text-muted">{stats.subtitle}</p>
      </div>
      <div className="mt-12 grid gap-8 sm:grid-cols-2 lg:grid-cols-4 font-ultimatum">
        {stats.items.map((item, i) => (
          <div key={i} className="text-center">
            <div className="text-3xl font-bold text-accent sm:text-4xl">
              {item.value}
            </div>
            <div className="mt-1 text-sm font-medium text-text-muted">
              {item.label}
            </div>
          </div>
        ))}
      </div>
    </Section>
  );
}
