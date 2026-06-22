import type { AegisEvent, Alert } from "../api";
import { SeverityBadge } from "./badges";
import { CrosshairIcon } from "./icons";

// Red Team view: open ports from the scanner (telemetry) + web vulnerabilities (alerts).
export function ScanPanel({ alerts, events }: { alerts: Alert[]; events: AegisEvent[] }) {
  const openPorts = events.filter((e) => e.event_type === "open_port");
  const vulns = alerts.filter((a) => a.rule_id.startsWith("vuln-"));

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">
          <span className="icon-slot h-7 w-7 bg-rose-500/10 text-rose-300 ring-1 ring-rose-400/20">
            <CrosshairIcon size={15} />
          </span>
          Tarama &amp; Varlıklar
        </span>
      </div>
      <div className="grid grid-cols-1 gap-5 p-5 sm:grid-cols-2">
        <div>
          <div className="mb-2.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            Açık Portlar ({openPorts.length})
          </div>
          <ul className="space-y-1.5 text-sm">
            {openPorts.length === 0 && <li className="text-slate-600">—</li>}
            {openPorts.slice(0, 8).map((e) => (
              <li key={e.id} className="font-mono text-emerald-300">
                {String(e.data.host ?? "")}:{String(e.data.port ?? "")}{" "}
                <span className="text-slate-500">{String(e.data.service ?? "")}</span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <div className="mb-2.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            Web Zafiyetleri ({vulns.length})
          </div>
          <ul className="space-y-2 text-sm">
            {vulns.length === 0 && <li className="text-slate-600">—</li>}
            {vulns.slice(0, 8).map((a) => (
              <li key={a.id} className="flex items-center gap-2">
                <SeverityBadge severity={a.severity} />
                <span className="text-slate-200">{a.title}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
