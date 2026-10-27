import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Bot, Hand, ListChecks } from "lucide-react";
import { api, type Decision } from "../api";
import { ago, claimedName, duration, kindEffect, kindLabel, until } from "../lib/format";
import { Button, ClassBadge, ErrorText, RiskBadge, Tag } from "./ui";

const sourceLabel = {
  llm: { icon: Bot, text: "Suggested by AI" },
  rules: { icon: ListChecks, text: "Suggested by rules" },
  manual: { icon: Hand, text: "Added by you" },
} as const;

const statusText = (d: Decision) => {
  switch (d.status) {
    case "pending":
      return `Suggested ${ago(d.created_at)}. Lasts ${duration(d.ttl_minutes)} once approved.`;
    case "active":
      return d.expires_at ? `Enforced. Ends ${until(d.expires_at)}.` : "Enforced.";
    case "expired":
      return d.expires_at ? `Ended ${ago(d.expires_at)}.` : "Ended.";
    case "rejected":
      return `Rejected ${d.decided_at ? ago(d.decided_at) : ""}.`;
    case "revoked":
      return `Revoked ${d.decided_at ? ago(d.decided_at) : ""}.`;
  }
};

const target = (d: Decision) => (d.ja4 ? `${d.ip}, this TLS fingerprint only` : `everything from ${d.ip}`);

/**
 * One decision with the actions its state allows. Inside a visitor's page
 * (inActor), the visitor and the AI's reasoning are already on screen, so the
 * row leaves them out.
 */
export function DecisionRow({
  d,
  onOpenActor,
  inActor = false,
}: {
  d: Decision;
  onOpenActor?: (id: number) => void;
  inActor?: boolean;
}) {
  const qc = useQueryClient();
  const act = useMutation({
    mutationFn: (verb: "approve" | "reject" | "revoke") => api.transition(d.id, verb),
    onSettled: () => qc.invalidateQueries(),
  });
  const Source = sourceLabel[d.source];
  const verb = d.kind === "rate_limit" ? `Rate limit to ${d.rpm}/min` : kindLabel[d.kind];
  const live = d.status === "pending" || d.status === "active";
  const actor = inActor ? undefined : d.actor;
  const showReason = d.reason && !(inActor && d.source === "llm");

  return (
    <div className={`flex flex-col gap-3 px-4 py-3.5 sm:flex-row sm:items-start ${live ? "" : "opacity-75"}`}>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="text-sm font-semibold">
            {verb}
            {actor && <span> {claimedName(actor.ua)}</span>}
          </span>
          {actor && <ClassBadge value={actor.class} />}
          {actor && <RiskBadge risk={actor.risk} />}
        </div>
        <p className="mt-0.5 font-mono text-xs text-ink-2">{target(d)}</p>
        {showReason && <p className="mt-2 text-sm leading-snug">{d.reason}</p>}
        {d.status === "pending" && <p className="mt-1 text-xs text-ink-2">{kindEffect[d.kind]}</p>}
        <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
          <Tag>
            <Source.icon className="mr-1 size-3" aria-hidden />
            {Source.text}
          </Tag>
          <span>{statusText(d)}</span>
          {onOpenActor && d.actor_id !== null && (
            <button
              type="button"
              className="underline decoration-line-strong underline-offset-2 hover:text-ink"
              onClick={() => d.actor_id !== null && onOpenActor(d.actor_id)}
            >
              Open visitor
            </button>
          )}
        </div>
        <ErrorText error={act.error} />
      </div>
      {live && (
        <div className="flex shrink-0 gap-2">
          {d.status === "pending" && (
            <>
              <Button disabled={act.isPending} onClick={() => act.mutate("reject")}>
                Reject
              </Button>
              <Button
                variant={d.kind === "block" ? "danger" : "primary"}
                disabled={act.isPending}
                onClick={() => act.mutate("approve")}
              >
                Approve {kindLabel[d.kind].toLowerCase()}
              </Button>
            </>
          )}
          {d.status === "active" && (
            <Button disabled={act.isPending} onClick={() => act.mutate("revoke")}>
              Revoke
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
