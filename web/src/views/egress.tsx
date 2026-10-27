import { useQuery } from "@tanstack/react-query";
import { TriangleAlert } from "lucide-react";
import { api, type EgressDest } from "../api";
import { Card, Empty } from "../components/ui";
import { ago } from "../lib/format";

const flagText: Record<EgressDest["flags"][number], string> = {
  new_destination: "new destination",
  uncommon_port: "uncommon port",
};

export function EgressView() {
  const egress = useQuery({ queryKey: ["egress"], queryFn: api.egress, refetchInterval: 10_000 });
  const rows = egress.data ?? [];

  return (
    <Card
      title="Outbound connections · last 24 hours"
      hint="Which processes on your servers connect where. A compromised box often shows up here first."
    >
      {rows.length === 0 ? (
        <Empty title="No outbound connections recorded">
          Start a sensor with <code className="font-mono text-xs">-egress</code> (as root, or with CAP_BPF and
          CAP_PERFMON) to see which processes on the box connect where. Destinations first seen after the
          first hour are flagged as new.
        </Empty>
      ) : (
        <div className="overflow-x-auto border-t border-line">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-muted">
              <tr className="border-b border-line">
                <th className="px-4 py-2 font-medium">Process</th>
                <th className="py-2 font-medium">Destination</th>
                <th className="px-2 py-2 text-right font-medium">Connections</th>
                <th className="px-2 py-2 font-medium">First seen</th>
                <th className="px-4 py-2 font-medium">Flags</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.map((e) => (
                <tr key={e.id} className="hover:bg-hover">
                  <td className="px-4 py-2">
                    <span className="font-mono">{e.comm}</span>
                    <span className="ml-2 text-xs text-muted">
                      uid {e.uid} · pid {e.last_pid}
                    </span>
                  </td>
                  <td className="py-2 font-mono">
                    {e.dst_ip}:{e.dst_port}
                  </td>
                  <td className="px-2 py-2 text-right tabular-nums">{e.connections}</td>
                  <td className="px-2 py-2 text-ink-2 whitespace-nowrap">{ago(e.first_seen)}</td>
                  <td className="px-4 py-2">
                    {e.flags.map((f) => (
                      <span key={f} className="mr-2 inline-flex items-center gap-1 text-xs text-ink-2">
                        <TriangleAlert className="size-3.5 text-serious" aria-hidden />
                        {flagText[f]}
                      </span>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
