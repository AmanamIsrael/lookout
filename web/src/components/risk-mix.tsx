import type { RiskBand } from "../api";
import { bandLabel, bands } from "../lib/format";
import { bandFill } from "./ui";

const bandRange: Record<RiskBand, string> = {
  hostile: "risk 80–100",
  suspicious: "risk 50–79",
  watch: "risk 20–49",
  benign: "risk 0–19",
};

/** Visitors split by risk band: one stacked bar plus a legend that carries the numbers. */
export function RiskMix({ counts }: { counts: Record<RiskBand, number> }) {
  const total = bands.reduce((n, b) => n + counts[b], 0);
  return (
    <div>
      <div className="flex h-2.5 gap-0.5" role="img" aria-label="Visitors by risk">
        {total === 0 ? (
          <span className="flex-1 rounded bg-line" />
        ) : (
          bands
            .filter((b) => counts[b] > 0)
            .map((b) => (
              <span
                key={b}
                className={`group relative rounded ${bandFill[b]}`}
                style={{ flexGrow: counts[b], flexBasis: 0, minWidth: 6 }}
              >
                <span className="pointer-events-none absolute bottom-full left-1/2 z-10 mb-2 hidden -translate-x-1/2 rounded-md bg-ink px-2 py-1 text-xs whitespace-nowrap text-page group-hover:block">
                  {counts[b]} {bandLabel[b].toLowerCase()} · {Math.round((counts[b] / total) * 100)}%
                </span>
              </span>
            ))
        )}
      </div>
      <ul className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-4">
        {bands.map((b) => (
          <li key={b} className="flex items-start gap-2">
            <span className={`mt-1.5 size-2 shrink-0 rounded-full ${bandFill[b]}`} aria-hidden />
            <div>
              <div className="text-sm">
                <span className="font-semibold tabular-nums">{counts[b]}</span>{" "}
                <span className="text-ink-2">{bandLabel[b]}</span>
              </div>
              <div className="text-[11px] text-muted">{bandRange[b]}</div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
