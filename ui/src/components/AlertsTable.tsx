import type { Alert } from "../api";
import { SeverityBadge } from "./badges";
import { BellIcon } from "./icons";

interface Props {
  alerts: Alert[];
  onStatusChange: (id: number, status: string) => void;
}

function fmt(ts: string) {
  return new Date(ts).toLocaleTimeString();
}

export function AlertsTable({ alerts, onStatusChange }: Props) {
  return (
    <div className="panel overflow-hidden">
      <div className="panel-header">
        <span className="panel-title">
          <span className="icon-slot h-7 w-7 bg-amber-500/10 text-amber-300 ring-1 ring-amber-400/20">
            <BellIcon size={15} />
          </span>
          Uyarılar
        </span>
        <span className="font-mono text-xs text-slate-500">{alerts.length} kayıt</span>
      </div>
      <div className="max-h-[60vh] overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="table-head">
            <tr>
              <th className="px-5 py-2.5">Önem</th>
              <th className="px-4 py-2.5">Başlık</th>
              <th className="px-4 py-2.5">Kural</th>
              <th className="px-4 py-2.5">Ajan</th>
              <th className="px-4 py-2.5">Zaman</th>
              <th className="px-4 py-2.5">Durum</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-12 text-center text-slate-600">
                  Henüz uyarı yok. Demo üretmek için{" "}
                  <code className="rounded bg-white/[0.04] px-1.5 py-0.5 text-xs">
                    scripts/simulate.py
                  </code>{" "}
                  komutunu çalıştırın.
                </td>
              </tr>
            )}
            {alerts.map((a) => (
              <tr key={a.id} className="row-hover border-t border-white/[0.04]">
                <td className="px-5 py-2.5 align-top">
                  <SeverityBadge severity={a.severity} />
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-slate-100">{a.title}</span>
                    {a.count > 1 && (
                      <span className="rounded-full bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs font-semibold text-slate-200">
                        ×{a.count}
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 text-xs text-slate-500">{a.description}</div>
                </td>
                <td className="px-4 py-2.5 font-mono text-xs text-slate-400">{a.rule_id}</td>
                <td className="px-4 py-2.5 text-slate-300">{a.agent_id ?? "—"}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-slate-400">{fmt(a.created_at)}</td>
                <td className="px-4 py-2.5">
                  <select
                    value={a.status}
                    onChange={(e) => onStatusChange(a.id, e.target.value)}
                    aria-label={`${a.title} için durum`}
                    className="cursor-pointer rounded-md border border-white/10 bg-white/[0.04] px-2 py-1 text-xs text-slate-200 transition-colors hover:border-white/20 focus:border-sky-400/50"
                  >
                    <option value="open">Açık</option>
                    <option value="triaged">İncelemede</option>
                    <option value="closed">Kapandı</option>
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
