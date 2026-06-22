import type { Alert } from "../api";
import { BarsIcon } from "./icons";

const COLORS: Record<string, string> = {
  high: "bg-red-500",
  medium: "bg-amber-500",
  low: "bg-slate-500",
};
const DOT: Record<string, string> = {
  high: "bg-red-500",
  medium: "bg-amber-500",
  low: "bg-slate-500",
};
const ORDER = ["high", "medium", "low"];
const LABEL: Record<string, string> = { high: "Yüksek", medium: "Orta", low: "Düşük" };

// Shows the severity distribution of alerts as a horizontal stacked bar.
export function SeverityChart({ alerts }: { alerts: Alert[] }) {
  const counts: Record<string, number> = { high: 0, medium: 0, low: 0 };
  for (const a of alerts) counts[a.severity] = (counts[a.severity] ?? 0) + 1;
  const total = alerts.length || 1;

  return (
    <div className="panel p-5">
      <div className="mb-3 flex items-center justify-between">
        <span className="panel-title">
          <span className="icon-slot h-7 w-7 bg-white/[0.04] text-slate-300 ring-1 ring-white/[0.06]">
            <BarsIcon size={15} />
          </span>
          Önem Dağılımı
        </span>
        <span className="font-mono text-xs text-slate-500">{alerts.length} uyarı</span>
      </div>
      <div className="flex h-2.5 w-full gap-0.5 overflow-hidden rounded-full bg-white/[0.04]">
        {ORDER.map((s) =>
          counts[s] > 0 ? (
            <div
              key={s}
              className={`${COLORS[s]} transition-all duration-500`}
              style={{ width: `${(counts[s] / total) * 100}%` }}
            />
          ) : null,
        )}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-xs">
        {ORDER.map((s) => (
          <span key={s} className="flex items-center gap-1.5 text-slate-400">
            <span className={`h-2 w-2 rounded-full ${DOT[s]}`} />
            <span>{LABEL[s] ?? s}</span>
            <span className="font-mono font-semibold text-slate-200">{counts[s] ?? 0}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
