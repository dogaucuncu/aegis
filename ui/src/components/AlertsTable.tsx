import type { Alert } from "../api";
import { SeverityBadge } from "./badges";

interface Props {
  alerts: Alert[];
  onStatusChange: (id: number, status: string) => void;
}

function fmt(ts: string) {
  return new Date(ts).toLocaleTimeString();
}

export function AlertsTable({ alerts, onStatusChange }: Props) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
        <h2 className="font-semibold text-slate-100">Alarmlar</h2>
        <span className="text-xs text-slate-400">{alerts.length} kayıt</span>
      </div>
      <div className="max-h-[60vh] overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 bg-slate-900 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-2">Önem</th>
              <th className="px-4 py-2">Başlık</th>
              <th className="px-4 py-2">Kural</th>
              <th className="px-4 py-2">Ajan</th>
              <th className="px-4 py-2">Zaman</th>
              <th className="px-4 py-2">Durum</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  Henüz alarm yok. <code>scripts/simulate.py</code> ile demo üret.
                </td>
              </tr>
            )}
            {alerts.map((a) => (
              <tr key={a.id} className="border-t border-slate-800/60 hover:bg-slate-800/30">
                <td className="px-4 py-2"><SeverityBadge severity={a.severity} /></td>
                <td className="px-4 py-2">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-slate-100">{a.title}</span>
                    {a.count > 1 && (
                      <span className="rounded-full bg-slate-700/70 px-1.5 py-0.5 text-xs font-semibold text-slate-200">
                        ×{a.count}
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-500">{a.description}</div>
                </td>
                <td className="px-4 py-2 font-mono text-xs text-slate-400">{a.rule_id}</td>
                <td className="px-4 py-2 text-slate-300">{a.agent_id ?? "—"}</td>
                <td className="px-4 py-2 text-slate-400">{fmt(a.created_at)}</td>
                <td className="px-4 py-2">
                  <select
                    value={a.status}
                    onChange={(e) => onStatusChange(a.id, e.target.value)}
                    className="rounded border border-slate-700 bg-slate-800 px-1.5 py-1 text-xs text-slate-200"
                  >
                    <option value="open">open</option>
                    <option value="triaged">triaged</option>
                    <option value="closed">closed</option>
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
