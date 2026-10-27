import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Bot, CircleCheck, Radio } from "lucide-react";
import { type Actor, type ActorFilter, api, type Overview } from "../api";
import { RiskMix } from "../components/risk-mix";
import { Button, ClassBadge, Empty, RiskScore, Segmented, VerifiedBadge } from "../components/ui";
import { ago, claimedName, modelName, plural } from "../lib/format";
import { useUrlParam } from "../lib/url";
import { ActorDetail } from "./actor-detail";

const filterLabels: Record<ActorFilter, string> = {
  suspicious: "Needs attention",
  agents: "AI agents",
  all: "Everyone",
  verified: "Verified",
  dismissed: "Dismissed",
};

const emptyCopy: Record<ActorFilter, string> = {
  suspicious: "Nothing needs attention in the last 24 hours.",
  agents: "No AI agents in the last 24 hours.",
  all: "No traffic yet. Add a sensor and point it at your app.",
  verified: "No verified bots or agents in the last 24 hours.",
  dismissed: "You haven't dismissed anyone.",
};

export function ActorsView({ onOpen }: { onOpen: (view: "decisions" | "egress") => void }) {
  const [filterParam, setFilter] = useUrlParam("filter");
  const [selectedParam, setSelected] = useUrlParam("actor");
  const filter = (filterParam && filterParam in filterLabels ? filterParam : "suspicious") as ActorFilter;
  const selected = selectedParam ? Number(selectedParam) : null;

  const overview = useQuery({ queryKey: ["overview"], queryFn: api.overview, refetchInterval: 5000 });
  const actors = useQuery({
    queryKey: ["actors", filter],
    queryFn: () => api.actors(filter),
    refetchInterval: 5000,
  });
  const s = overview.data?.stats;
  const counts: Partial<Record<ActorFilter, number>> = s
    ? { suspicious: s.bands.hostile + s.bands.suspicious, agents: s.agents_24h }
    : {};

  return (
    <div className="space-y-4">
      {overview.data && (
        <div className={selected ? "hidden lg:block" : ""}>
          <Summary overview={overview.data} onOpen={onOpen} />
        </div>
      )}

      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <section
          className={`overflow-hidden rounded-xl bg-surface shadow-card ring-1 ring-line ${selected ? "hidden lg:block" : ""}`}
          aria-label="Visitors"
        >
          <header className="space-y-2 border-b border-line px-3 py-3">
            <div className="flex items-baseline justify-between gap-2 px-1">
              <h2 className="text-sm font-semibold">Visitors</h2>
              <span className="text-xs text-muted">riskiest first</span>
            </div>
            <Segmented
              label="Filter visitors"
              value={filter}
              options={(Object.keys(filterLabels) as ActorFilter[]).map((f) => ({
                value: f,
                label: filterLabels[f],
                count: counts[f],
              }))}
              onChange={(v) => setFilter(v)}
            />
          </header>
          {actors.data?.length === 0 && <Empty title={emptyCopy[filter]} />}
          <ul className="divide-y divide-line lg:max-h-[calc(100vh-17rem)] lg:overflow-y-auto">
            {actors.data?.map((a) => (
              <li key={a.id}>
                <ActorRow actor={a} selected={a.id === selected} onSelect={() => setSelected(String(a.id))} />
              </li>
            ))}
          </ul>
        </section>

        <div className={selected ? "" : "hidden lg:block"}>
          {selected ? (
            <ActorDetail
              key={selected}
              id={selected}
              onClose={() => setSelected(null)}
              llm={overview.data?.llm ?? ""}
            />
          ) : (
            <div className="rounded-xl border border-dashed border-line-strong">
              <Empty title="Pick a visitor">
                You'll see what it is, why lookout thinks so, and what you can do about it.
              </Empty>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ActorRow({
  actor: a,
  selected,
  onSelect,
}: {
  actor: Actor;
  selected: boolean;
  onSelect: () => void;
}) {
  const why = a.triage?.summary ?? a.signals.find((x) => x.weight > 0)?.detail;
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-current={selected}
      className={`flex w-full gap-3 px-4 py-3 text-left transition-colors ${
        selected ? "bg-selected shadow-[inset_3px_0_0_var(--accent)]" : "hover:bg-hover"
      }`}
    >
      <RiskScore risk={a.risk} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-semibold">{claimedName(a.ua)}</span>
          <ClassBadge value={a.class} />
          {a.verified && <VerifiedBadge label={a.verified} />}
          <span className="ml-auto shrink-0 text-xs text-muted">{ago(a.last_seen)}</span>
        </div>
        {why && <p className="mt-1 line-clamp-2 text-sm leading-snug text-ink-2">{why}</p>}
        <div className="mt-1.5 flex flex-wrap items-center gap-x-1.5 text-xs text-muted">
          <span className="font-mono text-ink-2">{a.ip}</span>
          <span aria-hidden>·</span>
          <span className="tabular-nums">{plural(a.requests, "request")}</span>
          <span aria-hidden>·</span>
          <span className="inline-flex items-center gap-1">
            {a.triage ? <Bot className="size-3" aria-hidden /> : null}
            {a.triage ? "AI verdict" : "rules only"}
          </span>
        </div>
      </div>
    </button>
  );
}

function Summary({
  overview,
  onOpen,
}: {
  overview: Overview;
  onOpen: (view: "decisions" | "egress") => void;
}) {
  const s = overview.stats;
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
      <section className="rounded-xl bg-surface p-4 shadow-card ring-1 ring-line">
        <h2 className="text-xs font-medium text-muted">Last 24 hours</h2>
        <p className="mt-1 text-lg">
          <span className="font-semibold">{plural(s.actors_24h, "visitor")}</span>
          <span className="text-ink-2"> made </span>
          <span className="font-semibold">{plural(s.requests_24h, "request")}</span>
          {s.agents_24h > 0 && (
            <>
              <span className="text-ink-2">. </span>
              <span className="font-semibold">{plural(s.agents_24h, "AI agent")}</span>
              <span className="text-ink-2"> among them</span>
            </>
          )}
          <span className="text-ink-2">.</span>
        </p>
        <div className="mt-4">
          <RiskMix counts={s.bands} />
        </div>
      </section>

      <section className="flex flex-col rounded-xl bg-surface p-4 shadow-card ring-1 ring-line">
        <h2 className="text-xs font-medium text-muted">Waiting for you</h2>
        {s.pending_decisions > 0 ? (
          <>
            <p className="mt-1 text-lg">
              <span className="font-semibold">{plural(s.pending_decisions, "suggestion")}</span>
              <span className="text-ink-2"> to review</span>
            </p>
            <p className="mt-1 text-xs text-ink-2">Nothing is enforced until you approve it.</p>
            <Button variant="primary" className="mt-3 self-start" onClick={() => onOpen("decisions")}>
              Review now <ArrowRight className="size-3.5" aria-hidden />
            </Button>
          </>
        ) : (
          <p className="mt-1 inline-flex items-center gap-1.5 text-lg text-ink-2">
            <CircleCheck className="size-4 text-success-text" aria-hidden /> All caught up
          </p>
        )}
        <div className="mt-auto space-y-1.5 border-t border-line pt-3 text-xs text-ink-2 max-lg:mt-4">
          <p>
            <span className="font-semibold text-ink tabular-nums">{s.active_decisions}</span> enforced now
          </p>
          {s.flagged_egress > 0 && (
            <button
              type="button"
              onClick={() => onOpen("egress")}
              className="inline-flex items-center gap-1 underline decoration-line-strong underline-offset-2 hover:text-ink"
            >
              <Radio className="size-3.5" aria-hidden />
              {plural(s.flagged_egress, "outbound connection")} flagged
            </button>
          )}
          <p className="inline-flex items-center gap-1.5">
            <Bot className="size-3.5" aria-hidden />
            {overview.llm ? `AI triage on · ${modelName(overview.llm)}` : "AI triage off · rules only"}
          </p>
        </div>
      </section>
    </div>
  );
}
