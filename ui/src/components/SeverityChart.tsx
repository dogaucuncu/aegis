import type { Alert } from "../api";

const COLORS: Record<string, string> = {
  high: "bg-red-500",
  medium: "bg-amber-500",
  low: "bg-slate-500",
};
const ORDER = ["high", "medium", "low"];

// Alarmların önem dağılımını yatay yığılmış çubukla gösterir.
export function SeverityChart({ alerts }: { alerts: Alert[] }) {
  const counts: Record<string, number> = { high: 0, medium: 0, low: 0 };
  for (const a of alerts) counts[a.severity] = (counts[a.severity] ?? 0) + 1;
  const total = alerts.length || 1;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-400">Önem Dağılımı</span>
        <span className="text-xs text-slate-500">{alerts.length} alarm</span>
      </div>
      <div className="flex h-3 w-full overflow-hidden rounded-full bg-slate-800">
        {ORDER.map((s) =>
          counts[s] > 0 ? (
            <div key={s} className={COLORS[s]} style={{ width: `${(counts[s] / total) * 100}%` }} />
          ) : null,
        )}
      </div>
      <div className="mt-2 flex flex-wrap gap-4 text-xs">
        {ORDER.map((s) => (
          <span key={s} className="flex items-center gap-1.5 text-slate-400">
            <span className={`h-2 w-2 rounded-full ${COLORS[s]}`} />
            {s}: <span className="text-slate-200">{counts[s] ?? 0}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
