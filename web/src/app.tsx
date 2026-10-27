import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Eye } from "lucide-react";
import { type FormEvent, useState } from "react";
import { api } from "./api";
import { Button, ErrorText } from "./components/ui";
import { modelName } from "./lib/format";
import { useUrlParam } from "./lib/url";
import { ActorsView } from "./views/actors";
import { DecisionsView } from "./views/decisions";
import { EgressView } from "./views/egress";
import { SensorsView } from "./views/sensors";

const views = ["actors", "decisions", "egress", "sensors"] as const;
type View = (typeof views)[number];

export function App() {
  const session = useQuery({ queryKey: ["session"], queryFn: api.session });
  if (session.isPending) return null;
  if (!session.data?.authenticated) return <Login />;
  return <Shell />;
}

function Shell() {
  const qc = useQueryClient();
  const [viewParam, setView] = useUrlParam("view");
  const [, setActor] = useUrlParam("actor");
  const view: View = views.includes(viewParam as View) ? (viewParam as View) : "actors";
  const overview = useQuery({ queryKey: ["overview"], queryFn: api.overview, refetchInterval: 5000 });
  const logout = useMutation({ mutationFn: api.logout, onSuccess: () => qc.clear() });
  const pending = overview.data?.stats.pending_decisions ?? 0;
  const flagged = overview.data?.stats.flagged_egress ?? 0;

  const openActor = (id: number) => {
    setView("actors");
    setActor(String(id));
  };

  const tabs: { id: View; label: string; count?: number }[] = [
    { id: "actors", label: "Visitors" },
    { id: "decisions", label: "Review", count: pending },
    { id: "egress", label: "Outbound", count: flagged },
    { id: "sensors", label: "Sensors" },
  ];

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b border-line bg-surface/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 px-4">
          <a href="?" className="flex shrink-0 items-center gap-1.5 py-3 font-semibold">
            <Eye className="size-4.5 text-accent" aria-hidden />
            lookout
          </a>
          <nav
            className="-mb-px flex min-w-0 gap-1 overflow-x-auto max-sm:order-last max-sm:-mx-2 max-sm:w-full"
            aria-label="Sections"
          >
            {tabs.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setView(t.id)}
                aria-current={view === t.id ? "page" : undefined}
                className={`inline-flex shrink-0 items-center gap-1.5 border-b-2 px-2.5 py-3 text-sm max-sm:pt-1 transition-colors ${
                  view === t.id
                    ? "border-accent font-medium text-ink"
                    : "border-transparent text-ink-2 hover:text-ink"
                }`}
              >
                {t.label}
                {t.count ? (
                  <span className="rounded-full bg-accent px-1.5 text-xs leading-5 font-semibold text-on-accent tabular-nums">
                    {t.count}
                  </span>
                ) : null}
              </button>
            ))}
          </nav>
          <div className="ml-auto flex shrink-0 items-center gap-3">
            {overview.data && (
              <span className="hidden items-center gap-1.5 text-xs text-ink-2 md:inline-flex">
                <Bot className="size-3.5" aria-hidden />
                {overview.data.llm ? `AI triage · ${modelName(overview.data.llm)}` : "AI triage off"}
              </span>
            )}
            <Button variant="ghost" className="max-sm:px-2" onClick={() => logout.mutate()}>
              Sign out
            </Button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-5">
        {view === "actors" && <ActorsView onOpen={setView} />}
        {view === "decisions" && <DecisionsView onOpenActor={openActor} />}
        {view === "egress" && <EgressView />}
        {view === "sensors" && <SensorsView />}
      </main>
    </div>
  );
}

function Login() {
  const qc = useQueryClient();
  const [token, setToken] = useState("");
  const login = useMutation({
    mutationFn: () => api.login(token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["session"] }),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    login.mutate();
  };
  return (
    <div className="grid min-h-screen place-items-center p-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm space-y-4 rounded-xl bg-surface p-6 shadow-card ring-1 ring-line"
      >
        <div>
          <h1 className="flex items-center gap-1.5 text-lg font-semibold">
            <Eye className="size-5 text-accent" aria-hidden /> lookout
          </h1>
          <p className="mt-1 text-sm text-ink-2">Sign in with the server's admin token.</p>
        </div>
        <div className="space-y-1.5">
          <label htmlFor="token" className="text-sm font-medium">
            Admin token
          </label>
          <input
            id="token"
            type="password"
            autoComplete="current-password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            className="h-9 w-full rounded-md bg-raised px-3 font-mono text-sm ring-1 ring-line-strong"
          />
        </div>
        <ErrorText error={login.error} />
        <Button
          type="submit"
          variant="primary"
          className="w-full justify-center"
          disabled={!token || login.isPending}
        >
          Sign in
        </Button>
      </form>
    </div>
  );
}
