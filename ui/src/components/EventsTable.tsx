import type { AegisEvent } from "../api";

interface Props {
  events: AegisEvent[];
}

function fmt(ts: string) {
  return new Date(ts).toLocaleTimeString();
}

const TYPE_COLORS: Record<string, string> = {
  process: "text-cyan-300",
  network: "text-violet-300",
  auth_failure: "text-amber-300",
  port_scan: "text-red-300",
  open_port: "text-emerald-300",
  vuln_finding: "text-red-400",
  file_change: "text-orange-300",
};

export function EventsTable({ events }: Props) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
        <h2 className="font-semibold text-slate-100">Telemetri Akışı</h2>
        <span className="text-xs text-slate-400">{events.length} olay</span>
      </div>
      <div className="max-h-[60vh] overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-2">#</th>
              <th className="px-4 py-2">Tür</th>
              <th className="px-4 py-2">Ajan</th>
              <th className="px-4 py-2">Özet</th>
              <th className="px-4 py-2">Zaman</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} className="border-t border-slate-800/60 hover:bg-slate-800/30">
                <td className="px-4 py-2 font-mono text-xs text-slate-500">{e.id}</td>
                <td className={`px-4 py-2 font-mono text-xs ${TYPE_COLORS[e.event_type] ?? "text-slate-300"}`}>
                  {e.signed && <span title="Güvenli (imzalı) kanal">🔒 </span>}
                  {e.event_type}
                </td>
                <td className="px-4 py-2 text-slate-300">{e.agent_id}</td>
                <td className="px-4 py-2 font-mono text-xs text-slate-400">
                  {summarize(e)}
                </td>
                <td className="px-4 py-2 text-slate-400">{fmt(e.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function summarize(e: AegisEvent): string {
  const d = e.data ?? {};
  if (e.event_type === "process") return String(d.cmdline ?? d.name ?? "");
  if (e.event_type === "network") return `${d.laddr ?? "?"} → ${d.raddr ?? "?"}`;
  if (e.event_type === "auth_failure") return `${d.username ?? "?"} @ ${d.source_ip ?? "?"}`;
  if (e.event_type === "port_scan") return `${d.source_ip ?? "?"} → ${d.target ?? "?"}`;
  if (e.event_type === "open_port") return `${d.host ?? "?"}:${d.port} (${d.service ?? "?"})`;
  if (e.event_type === "vuln_finding") return `${String(d.type ?? "").toUpperCase()} @ ${d.url ?? "?"} [${d.param ?? ""}]`;
  if (e.event_type === "file_change") return `${d.action ?? "?"}: ${d.path ?? "?"}`;
  return JSON.stringify(d).slice(0, 80);
}
