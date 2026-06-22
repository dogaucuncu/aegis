import type { AegisEvent } from "../api";
import { ServerIcon, LockIcon } from "./icons";

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
    <div className="panel overflow-hidden">
      <div className="panel-header">
        <span className="panel-title">
          <span className="icon-slot h-7 w-7 bg-sky-500/10 text-sky-300 ring-1 ring-sky-400/20">
            <ServerIcon size={15} />
          </span>
          Telemetri Akışı
        </span>
        <span className="font-mono text-xs text-slate-500">{events.length} olay</span>
      </div>
      <div className="max-h-[60vh] overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="table-head">
            <tr>
              <th className="px-5 py-2.5">#</th>
              <th className="px-4 py-2.5">Tür</th>
              <th className="px-4 py-2.5">Ajan</th>
              <th className="px-4 py-2.5">Özet</th>
              <th className="px-4 py-2.5">Zaman</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-12 text-center text-slate-600">
                  Henüz telemetri yok.
                </td>
              </tr>
            )}
            {events.map((e) => (
              <tr key={e.id} className="row-hover border-t border-white/[0.04]">
                <td className="px-5 py-2.5 font-mono text-xs text-slate-500">{e.id}</td>
                <td
                  className={`px-4 py-2.5 font-mono text-xs ${TYPE_COLORS[e.event_type] ?? "text-slate-300"}`}
                >
                  <span className="inline-flex items-center gap-1.5">
                    {e.signed && (
                      <LockIcon size={12} className="text-emerald-400" aria-label="Güvenli (imzalı) kanal" />
                    )}
                    {e.event_type}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-slate-300">{e.agent_id}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-slate-400">{summarize(e)}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-slate-400">{fmt(e.timestamp)}</td>
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
  if (e.event_type === "vuln_finding")
    return `${String(d.type ?? "").toUpperCase()} @ ${d.url ?? "?"} [${d.param ?? ""}]`;
  if (e.event_type === "file_change") return `${d.action ?? "?"}: ${d.path ?? "?"}`;
  return JSON.stringify(d).slice(0, 80);
}
