import type { AegisEvent, Alert } from "../api";
import { SeverityBadge } from "./badges";

// Red Team görünümü: tarayıcıdan gelen açık portlar (telemetri) + web zafiyetleri (alarm).
export function ScanPanel({ alerts, events }: { alerts: Alert[]; events: AegisEvent[] }) {
  const openPorts = events.filter((e) => e.event_type === "open_port");
  const vulns = alerts.filter((a) => a.rule_id.startsWith("vuln-"));

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
      <div className="border-b border-slate-800 px-4 py-3 font-semibold text-slate-100">
        ⚔️ Tarama & Varlıklar
      </div>
      <div className="grid grid-cols-1 gap-4 p-4 sm:grid-cols-2">
        <div>
          <div className="mb-2 text-xs uppercase tracking-wider text-slate-400">
            Açık Portlar ({openPorts.length})
          </div>
          <ul className="space-y-1 text-sm">
            {openPorts.length === 0 && <li className="text-slate-500">—</li>}
            {openPorts.slice(0, 8).map((e) => (
              <li key={e.id} className="font-mono text-emerald-300">
                {String(e.data.host ?? "")}:{String(e.data.port ?? "")}{" "}
                <span className="text-slate-500">{String(e.data.service ?? "")}</span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <div className="mb-2 text-xs uppercase tracking-wider text-slate-400">
            Web Zafiyetleri ({vulns.length})
          </div>
          <ul className="space-y-1.5 text-sm">
            {vulns.length === 0 && <li className="text-slate-500">—</li>}
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
