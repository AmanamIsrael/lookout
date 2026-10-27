import { useQuery } from "@tanstack/react-query";
import { api, type Decision } from "../api";
import { DecisionRow } from "../components/decision-row";
import { Card, Empty } from "../components/ui";

export function DecisionsView({ onOpenActor }: { onOpenActor: (id: number) => void }) {
  const decisions = useQuery({ queryKey: ["decisions"], queryFn: api.decisions, refetchInterval: 5000 });
  const all = decisions.data ?? [];
  const pending = all.filter((d) => d.status === "pending");
  const active = all.filter((d) => d.status === "active");
  const past = all.filter((d) => d.status !== "pending" && d.status !== "active");
  const rows = (list: Decision[]) => (
    <div className="divide-y divide-line border-t border-line">
      {list.map((d) => (
        <DecisionRow key={d.id} d={d} onOpenActor={onOpenActor} />
      ))}
    </div>
  );

  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <Card
        title={`Waiting for you · ${pending.length}`}
        hint="The AI and the rules suggest. You decide. Nothing is enforced until you approve it."
      >
        {pending.length === 0 ? (
          <Empty title="No suggestions to review">
            When a visitor looks like it should be blocked, challenged or slowed down, the suggestion lands
            here.
          </Empty>
        ) : (
          rows(pending)
        )}
      </Card>

      <Card
        title={`Enforced now · ${active.length}`}
        hint="Sensors apply these within a few seconds. Revoke to stop."
      >
        {active.length === 0 ? <Empty title="Nothing is being enforced" /> : rows(active)}
      </Card>

      {past.length > 0 && (
        <Card title="History" hint="Rejected suggestions don't come back for a day.">
          {rows(past)}
        </Card>
      )}
    </div>
  );
}
