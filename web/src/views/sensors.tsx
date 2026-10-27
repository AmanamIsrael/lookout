import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy } from "lucide-react";
import { type FormEvent, useState } from "react";
import { api, type Sensor } from "../api";
import { Button, Card, Empty, ErrorText } from "../components/ui";
import { ago } from "../lib/format";

const online = (s: Sensor) =>
  s.last_seen_at !== null && Date.now() - new Date(s.last_seen_at).getTime() < 30_000;

export function SensorsView() {
  const qc = useQueryClient();
  const sensors = useQuery({ queryKey: ["sensors"], queryFn: api.sensors, refetchInterval: 5000 });
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: () => api.createSensor(name.trim()),
    onSuccess: () => {
      setName("");
      qc.invalidateQueries({ queryKey: ["sensors"] });
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => api.deleteSensor(id),
    onSettled: () => qc.invalidateQueries({ queryKey: ["sensors"] }),
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (name.trim()) create.mutate();
  };

  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <Card
        title="Add a sensor"
        hint="A sensor is a small proxy in front of your app. It records traffic and enforces your decisions."
      >
        <form onSubmit={submit} className="flex flex-wrap items-center gap-2 px-4 pb-4">
          <label className="sr-only" htmlFor="sensor-name">
            Sensor name
          </label>
          <input
            id="sensor-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. web-1"
            maxLength={80}
            className="h-8 w-56 rounded-md bg-raised px-3 text-sm ring-1 ring-line-strong placeholder:text-muted"
          />
          <Button type="submit" variant="primary" disabled={!name.trim() || create.isPending}>
            Create key
          </Button>
          <ErrorText error={create.error} />
        </form>
        {create.data && <NewKey name={create.data.sensor.name} sensorKey={create.data.key} />}
      </Card>

      <Card title="Sensors">
        {sensors.data?.length === 0 ? (
          <Empty title="No sensors yet">
            Create a key above, then run lookout-sensor in front of your app.
          </Empty>
        ) : (
          <ul className="divide-y divide-line border-t border-line">
            {sensors.data?.map((s) => (
              <li key={s.id} className="flex items-center gap-3 px-4 py-3 text-sm">
                <span
                  className={`size-2 rounded-full ${online(s) ? "bg-good" : "bg-line-strong"}`}
                  aria-hidden
                />
                <span className="font-medium">{s.name}</span>
                <span className="text-xs text-ink-2">
                  {online(s)
                    ? "online"
                    : s.last_seen_at
                      ? `last seen ${ago(s.last_seen_at)}`
                      : "never connected"}
                  {s.egress_since && " · egress on"}
                  {s.dropped > 0 && ` · dropped ${s.dropped} events under load`}
                </span>
                <Button
                  variant="ghost"
                  className="ml-auto"
                  disabled={remove.isPending}
                  onClick={() => {
                    if (confirm(`Delete ${s.name}? Its key stops working and its data is removed.`))
                      remove.mutate(s.id);
                  }}
                >
                  Delete
                </Button>
              </li>
            ))}
          </ul>
        )}
        <div className="px-4 pb-3">
          <ErrorText error={remove.error} />
        </div>
      </Card>
    </div>
  );
}

function NewKey({ name, sensorKey }: { name: string; sensorKey: string }) {
  const [copied, setCopied] = useState(false);
  const command = [
    `LOOKOUT_KEY=${sensorKey} \\`,
    "lookout-sensor \\",
    `  -server ${location.origin} \\`,
    "  -upstream http://127.0.0.1:3000 \\",
    "  -listen :443 -domain your-site.example \\",
    "  -egress",
  ].join("\n");
  return (
    <div className="space-y-2 border-t border-line p-4">
      <p className="text-sm">
        Key for <span className="font-medium">{name}</span>. It's shown once; copy it now.
      </p>
      <div className="relative">
        <pre className="overflow-x-auto rounded-md bg-page p-3 font-mono text-xs leading-relaxed ring-1 ring-line">
          {command}
        </pre>
        <Button
          variant="secondary"
          className="absolute top-2 right-2"
          onClick={() => {
            navigator.clipboard.writeText(command);
            setCopied(true);
          }}
        >
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      <p className="text-xs text-ink-2">
        Set <code className="font-mono">-upstream</code> to your app and{" "}
        <code className="font-mono">-domain</code> to get a Let's Encrypt certificate (or pass{" "}
        <code className="font-mono">-tls-cert</code>/<code className="font-mono">-tls-key</code>). Behind a
        CDN, add <code className="font-mono">-trust-proxy</code> with its ranges.{" "}
        <code className="font-mono">-egress</code> needs root.
      </p>
    </div>
  );
}
