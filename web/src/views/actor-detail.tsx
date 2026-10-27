import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Bot, ShieldAlert, ShieldCheck, Sparkles } from "lucide-react";
import { useState } from "react";
import {
  type Actor,
  api,
  type Decision,
  type EnforcementKind,
  type RequestEvent,
  type Verdict,
} from "../api";
import { DecisionRow } from "../components/decision-row";
import { Button, Card, ClassBadge, Empty, ErrorText, RiskScore, Segmented, Tag } from "../components/ui";
import {
  ago,
  claimedName,
  classLabel,
  classMeaning,
  clock,
  duration,
  kindEffect,
  kindLabel,
  modelName,
  plural,
} from "../lib/format";

export function ActorDetail({ id, onClose, llm }: { id: number; onClose: () => void; llm: string }) {
  const detail = useQuery({ queryKey: ["actor", id], queryFn: () => api.actor(id), refetchInterval: 5000 });

  if (detail.error) {
    return (
      <Card>
        <Empty title="Couldn't load this visitor">
          <ErrorText error={detail.error} />
        </Empty>
      </Card>
    );
  }
  if (!detail.data) return null;
  const { actor, requests, decisions } = detail.data;

  return (
    <div className="space-y-4">
      <Header actor={actor} onClose={onClose} />
      <VerdictCard actor={actor} llm={llm} />
      <ActCard actor={actor} decisions={decisions} />
      <IdentityCard actor={actor} />
      <SignalsCard actor={actor} />
      <RequestsCard requests={requests} />
    </div>
  );
}

function Header({ actor, onClose }: { actor: Actor; onClose: () => void }) {
  const qc = useQueryClient();
  const dismiss = useMutation({
    mutationFn: () => api.dismiss(actor.id, actor.dismissed_at === null),
    onSettled: () => qc.invalidateQueries(),
  });
  return (
    <Card>
      <div className="p-4">
        <div className="flex items-center justify-between gap-2 lg:hidden">
          <Button variant="ghost" className="-ml-2" onClick={onClose}>
            <ArrowLeft className="size-4" aria-hidden /> Visitors
          </Button>
        </div>
        <div className="flex flex-wrap items-start gap-x-6 gap-y-4 max-lg:mt-2">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-xl font-semibold">{claimedName(actor.ua)}</h1>
              <ClassBadge value={actor.class} />
            </div>
            <p className="mt-1 text-sm text-ink-2">{classMeaning[actor.class]}</p>
            <p className="mt-2 text-xs text-muted">
              <span className="font-mono text-ink-2">{actor.ip}</span> · {plural(actor.requests, "request")} ·
              first seen {ago(actor.first_seen)} · last seen {ago(actor.last_seen)}
            </p>
          </div>
          <RiskScore risk={actor.risk} size="lg" />
        </div>
        <div className="mt-3 flex items-center gap-3 border-t border-line pt-3">
          <p className="flex-1 text-xs text-muted">
            {actor.dismissed_at
              ? `Dismissed ${ago(actor.dismissed_at)}. Hidden from the default lists.`
              : "Dismiss hides a visitor you've decided is fine."}
          </p>
          <Button disabled={dismiss.isPending} onClick={() => dismiss.mutate()}>
            {actor.dismissed_at ? "Restore" : "Dismiss"}
          </Button>
        </div>
        <ErrorText error={dismiss.error} />
      </div>
    </Card>
  );
}

const actionText: Record<Verdict["recommended_action"], string> = {
  none: "No action needed",
  watch: "Keep watching",
  block: "Block",
  challenge: "Challenge",
  rate_limit: "Rate limit",
};

/** What lookout thinks: the AI verdict when there is one, the rules otherwise. */
function VerdictCard({ actor, llm }: { actor: Actor; llm: string }) {
  const qc = useQueryClient();
  const run = useMutation({
    mutationFn: () => api.triage(actor.id),
    onSettled: () => qc.invalidateQueries(),
  });
  const v = actor.triage;
  const topSignals = actor.signals.filter((s) => s.weight > 0).slice(0, 3);

  return (
    <Card
      title="What's going on"
      hint={
        v
          ? `AI verdict · ${modelName(v.model)} · ${actor.triaged_at ? ago(actor.triaged_at) : ""}`
          : "From the rules. No AI verdict yet."
      }
      action={
        llm ? (
          <Button variant={v ? "ghost" : "primary"} disabled={run.isPending} onClick={() => run.mutate()}>
            <Sparkles className="size-3.5" aria-hidden />
            {run.isPending ? "Asking…" : v ? "Ask again" : "Ask AI"}
          </Button>
        ) : undefined
      }
    >
      <div className="space-y-3 px-4 pb-4">
        {run.isPending && (
          <p className="rounded-lg bg-sunken px-3 py-2 text-sm text-ink-2 ring-1 ring-line">
            {modelName(llm)} is reading this visitor's requests. This takes a few seconds.
          </p>
        )}
        <ErrorText error={run.error} />

        {v ? (
          <>
            <p className="text-[15px] leading-relaxed">{v.summary}</p>
            {v.evidence.length > 0 && (
              <ul className="space-y-1.5 text-sm text-ink-2">
                {v.evidence.map((e) => (
                  <li key={e} className="flex gap-2">
                    <span className="mt-2 size-1 shrink-0 rounded-full bg-muted" aria-hidden />
                    <span>{e}</span>
                  </li>
                ))}
              </ul>
            )}
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-lg bg-sunken px-3 py-2 text-sm ring-1 ring-line">
              <span>
                <span className="text-muted">Recommends </span>
                <span className="font-semibold">{actionText[v.recommended_action]}</span>
                {v.recommended_action !== "none" && v.recommended_action !== "watch" && (
                  <span className="text-ink-2">
                    {" "}
                    · {v.scope === "fingerprint" ? "this fingerprint" : "the whole IP"} ·{" "}
                    {duration(v.ttl_minutes)}
                  </span>
                )}
              </span>
              <span className="ml-auto text-xs text-muted">{Math.round(v.confidence * 100)}% confident</span>
            </div>
            {v.risk !== actor.rule_score && (
              <p className="text-xs text-muted">
                The rules scored this {actor.rule_score} as {classLabel[actor.class].toLowerCase()}. The AI's
                score {v.risk} is the one shown.
              </p>
            )}
          </>
        ) : (
          <>
            {topSignals.length === 0 ? (
              <p className="text-sm text-ink-2">No rule found anything unusual about this visitor.</p>
            ) : (
              <ul className="space-y-1.5 text-sm">
                {topSignals.map((s) => (
                  <li key={s.code} className="flex gap-2">
                    <span className="mt-2 size-1 shrink-0 rounded-full bg-muted" aria-hidden />
                    <span>{s.detail}</span>
                  </li>
                ))}
              </ul>
            )}
            <p className="text-xs text-muted">
              {!llm
                ? "AI triage is off. Set OPENROUTER_API_KEY or ANTHROPIC_API_KEY on the server to get a second opinion."
                : actor.rule_score >= 25
                  ? "Queued for the AI: it reads every visitor the rules score 25 or more. Ask now to skip the queue."
                  : "The rules don't send this visitor to the AI. Ask if you want a second opinion."}
            </p>
          </>
        )}
      </div>
    </Card>
  );
}

const durations = [
  { value: 60, label: "1 hour" },
  { value: 360, label: "6 hours" },
  { value: 1440, label: "1 day" },
  { value: 10080, label: "1 week" },
];

type Plan = { kind: EnforcementKind; scope: "ip" | "fingerprint"; ttl: number };

/** Everything you can do about this visitor, in one place. */
function ActCard({ actor, decisions }: { actor: Actor; decisions: Decision[] }) {
  const open = decisions.filter((d) => d.status === "pending" || d.status === "active");
  const past = decisions.filter((d) => d.status !== "pending" && d.status !== "active");
  const v = actor.triage;
  const recommended: Plan | null =
    v && v.recommended_action !== "none" && v.recommended_action !== "watch"
      ? { kind: v.recommended_action, scope: actor.ja4 ? v.scope : "ip", ttl: v.ttl_minutes }
      : null;

  return (
    <Card
      title="What to do"
      hint={
        open.some((d) => d.status === "pending")
          ? "A suggestion is waiting. Nothing is enforced until you approve it."
          : "Decisions reach every sensor within a few seconds."
      }
    >
      {open.length > 0 && (
        <div className="divide-y divide-line border-t border-line">
          {open.map((d) => (
            <DecisionRow key={d.id} d={d} inActor />
          ))}
        </div>
      )}
      <div className="border-t border-line p-4">
        {open.length === 0 && recommended ? (
          <ManualForm actor={actor} initial={recommended} fromAI />
        ) : (
          <details className="group" open={open.length === 0 && !recommended}>
            <summary className="cursor-pointer text-sm font-medium text-ink-2 select-none hover:text-ink">
              {open.length > 0 ? "Do something else" : "Act now"}
            </summary>
            <div className="mt-3">
              <ManualForm
                actor={actor}
                initial={{ kind: "challenge", scope: actor.ja4 ? "fingerprint" : "ip", ttl: 1440 }}
              />
            </div>
          </details>
        )}
      </div>
      {past.length > 0 && (
        <details className="border-t border-line">
          <summary className="cursor-pointer px-4 py-2.5 text-xs font-medium text-muted select-none hover:text-ink">
            {plural(past.length, "past decision")}
          </summary>
          <div className="divide-y divide-line border-t border-line">
            {past.map((d) => (
              <DecisionRow key={d.id} d={d} inActor />
            ))}
          </div>
        </details>
      )}
    </Card>
  );
}

function ManualForm({ actor, initial, fromAI }: { actor: Actor; initial: Plan; fromAI?: boolean }) {
  const qc = useQueryClient();
  const [plan, setPlan] = useState(initial);
  const create = useMutation({
    mutationFn: () =>
      api.createDecision({
        actor_id: actor.id,
        ip: actor.ip,
        ja4: plan.scope === "fingerprint" ? actor.ja4 : undefined,
        kind: plan.kind,
        rpm: plan.kind === "rate_limit" ? 60 : undefined,
        ttl_minutes: plan.ttl,
        reason:
          fromAI && plan === initial
            ? (actor.triage?.summary ?? "")
            : `Manual ${kindLabel[plan.kind].toLowerCase()} from the dashboard`,
      }),
    onSettled: () => qc.invalidateQueries(),
  });
  const target = plan.scope === "fingerprint" ? "this fingerprint" : `all of ${actor.ip}`;
  const verb = plan.kind === "rate_limit" ? "Rate limit (60/min)" : kindLabel[plan.kind];
  const ttlOptions = durations.some((d) => d.value === plan.ttl)
    ? durations
    : [...durations, { value: plan.ttl, label: duration(plan.ttl) }].sort((a, b) => a.value - b.value);

  return (
    <div className="space-y-3">
      {fromAI && (
        <p className="inline-flex items-center gap-1.5 text-sm font-medium">
          <Bot className="size-4" aria-hidden /> The AI's recommendation, ready to apply
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Segmented
          label="Action"
          value={plan.kind}
          onChange={(kind) => setPlan({ ...plan, kind })}
          options={[
            { value: "challenge", label: "Challenge" },
            { value: "rate_limit", label: "Rate limit" },
            { value: "block", label: "Block" },
          ]}
        />
        {actor.ja4 && (
          <Segmented
            label="Scope"
            value={plan.scope}
            onChange={(scope) => setPlan({ ...plan, scope })}
            options={[
              { value: "fingerprint", label: "This fingerprint" },
              { value: "ip", label: "Whole IP" },
            ]}
          />
        )}
        <select
          aria-label="Duration"
          value={plan.ttl}
          onChange={(e) => setPlan({ ...plan, ttl: Number(e.target.value) })}
          className="h-7 rounded-md bg-raised px-2 text-xs ring-1 ring-line-strong"
        >
          {ttlOptions.map((d) => (
            <option key={d.value} value={d.value}>
              {d.label}
            </option>
          ))}
        </select>
      </div>
      <p className="text-xs leading-relaxed text-ink-2">
        {kindEffect[plan.kind]}
        {plan.scope === "ip" && " A whole IP can be shared by an office, a NAT or a mobile carrier."}
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <Button
          variant={plan.kind === "block" ? "danger" : "primary"}
          disabled={create.isPending}
          onClick={() => create.mutate()}
        >
          {verb} {target} for {duration(plan.ttl)}
        </Button>
        {create.isSuccess && <span className="text-xs text-success-text">Sent to sensors</span>}
      </div>
      <ErrorText error={create.error} />
    </div>
  );
}

function IdentityCard({ actor }: { actor: Actor }) {
  const failed = actor.signals.find((s) => s.code === "identity_failed");
  return (
    <Card title="Identity" hint="Who it says it is, and what lookout could prove.">
      <dl className="grid gap-x-4 gap-y-2.5 px-4 pb-4 text-sm sm:grid-cols-[9rem_1fr]">
        <dt className="text-muted">Proof</dt>
        <dd>
          {actor.verified ? (
            <span className="inline-flex items-start gap-1.5 text-success-text">
              <ShieldCheck className="mt-0.5 size-4 shrink-0" aria-hidden /> {actor.verified}
            </span>
          ) : failed ? (
            <span className="inline-flex items-start gap-1.5 text-critical-text">
              <ShieldAlert className="mt-0.5 size-4 shrink-0" aria-hidden /> {failed.detail}
            </span>
          ) : (
            <span className="text-ink-2">
              None. It didn't sign its requests, and it doesn't claim to be a bot lookout can check.
            </span>
          )}
        </dd>
        <dt className="text-muted">Says it is</dt>
        <dd className="font-mono text-xs leading-5 break-all">{actor.ua || "no user agent"}</dd>
        <dt className="text-muted">IP address</dt>
        <dd className="font-mono text-xs leading-5">{actor.ip}</dd>
        <dt className="text-muted">TLS fingerprint</dt>
        <dd className="text-xs leading-5">
          <span className="font-mono break-all">{actor.ja4 || "none (plain HTTP)"}</span>
          <span className="mt-0.5 block text-muted">
            JA4: how its TLS library says hello. Browsers and scripts look different here, whatever they
            claim.
          </span>
        </dd>
      </dl>
    </Card>
  );
}

function SignalsCard({ actor }: { actor: Actor }) {
  const max = Math.max(1, ...actor.signals.map((s) => Math.abs(s.weight)));
  return (
    <Card
      title={`Rule signals · score ${actor.rule_score}`}
      hint="Each rule that fired adds or removes points. The total is capped at 0–100."
    >
      {actor.signals.length === 0 ? (
        <Empty title="No rule fired for this visitor" />
      ) : (
        <ul className="divide-y divide-line border-t border-line">
          {actor.signals.map((s) => (
            <li key={s.code} className="flex items-start gap-3 px-4 py-2.5 text-sm">
              <span className="w-14 shrink-0 pt-0.5">
                <span className="block font-mono text-xs text-ink-2 tabular-nums">
                  {s.weight > 0 ? `+${s.weight}` : s.weight}
                </span>
                <span className="mt-1 block h-1 rounded-full bg-line">
                  <span
                    className={`block h-full rounded-full ${s.weight > 0 ? "bg-ink-2" : "bg-good"}`}
                    style={{ width: `${(Math.abs(s.weight) / max) * 100}%` }}
                  />
                </span>
              </span>
              <span>{s.detail}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

const actionTag: Record<RequestEvent["action"], string | null> = {
  allow: null,
  block: "blocked",
  challenge: "challenged",
  challenge_passed: "passed check",
  rate_limit: "rate limited",
};

function RequestsCard({ requests }: { requests: RequestEvent[] }) {
  const rows = [...requests].reverse();
  return (
    <Card
      title={`Recent requests · ${requests.length}`}
      hint="Newest first. Sensitive query values are redacted at the sensor."
    >
      <div className="max-h-[32rem] overflow-auto border-t border-line">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-surface text-left text-muted">
            <tr className="border-b border-line">
              <th className="w-px px-4 py-2 font-medium">Time</th>
              <th className="py-2 font-medium">Request</th>
              <th className="w-px px-2 py-2 text-right font-medium">Status</th>
              <th className="w-px px-4 py-2 text-right font-medium max-sm:hidden">ms</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((r, i) => (
              // Requests have no id and two can share a timestamp; the list only ever re-renders whole.
              // biome-ignore lint/suspicious/noArrayIndexKey: see above
              <tr key={`${r.ts}-${i}`} className="hover:bg-hover">
                <td className="px-4 py-1.5 whitespace-nowrap text-ink-2 tabular-nums">{clock(r.ts)}</td>
                <td className="max-w-0 py-1.5 font-mono">
                  <div className="truncate" title={`${r.method} ${r.path}${r.query ? `?${r.query}` : ""}`}>
                    <span className="text-muted">{r.method} </span>
                    {r.path}
                    {r.query && <span className="text-muted">?{r.query}</span>}
                  </div>
                </td>
                <td className="px-2 py-1.5 text-right whitespace-nowrap tabular-nums">
                  {actionTag[r.action] && <Tag>{actionTag[r.action]}</Tag>}{" "}
                  <span className={r.status >= 400 ? "font-semibold" : "text-ink-2"}>{r.status}</span>
                </td>
                <td className="px-4 py-1.5 text-right text-ink-2 tabular-nums max-sm:hidden">
                  {r.duration_ms.toFixed(0)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
