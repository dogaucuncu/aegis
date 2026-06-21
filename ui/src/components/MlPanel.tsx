import type { Alert } from "../api";

// ML görünümü: NIDS anomali + phishing tespitleri (rule_id "ml-*").
export function MlPanel({ alerts }: { alerts: Alert[] }) {
  const ml = alerts.filter((a) => a.rule_id.startsWith("ml-"));

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
        <span className="font-semibold text-slate-100">🤖 ML Tespitleri</span>
        <span className="text-xs text-slate-400">{ml.length} kayıt</span>
      </div>
      <ul className="max-h-72 divide-y divide-slate-800/60 overflow-auto">
        {ml.length === 0 && (
          <li className="px-4 py-8 text-center text-sm text-slate-500">ML tespiti yok</li>
        )}
        {ml.map((a) => (
          <li key={a.id} className="px-4 py-2">
            <div className="text-sm font-medium text-violet-300">{a.title}</div>
            <div className="font-mono text-xs text-slate-500">{a.description}</div>
          </li>
        ))}
      </ul>
    </div>
  );
}
