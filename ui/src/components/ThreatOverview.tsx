import type { Stats } from "../api";
import { TargetIcon } from "./icons";

function Bar({ label, value, max, tone }: { label: string; value: number; max: number; tone: string }) {
  const pct = Math.round((value / (max || 1)) * 100);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="truncate text-slate-300">{label}</span>
        <span className="ml-2 shrink-0 font-mono font-semibold tabular-nums text-slate-400">{value}</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/[0.05]">
        <div
          className={`h-full rounded-full ${tone} transition-all duration-500`}
          style={{ width: `${Math.max(pct, 4)}%` }}
        />
      </div>
    </div>
  );
}

// Surfaces /api/stats: MITRE ATT&CK tactic distribution + the most-triggered detection rules.
export function ThreatOverview({ stats }: { stats?: Stats | null }) {
  const tactics = Object.entries(stats?.by_tactic ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const rules = Object.entries(stats?.by_rule ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 7);
  const maxT = tactics.length ? tactics[0][1] : 0;
  const empty = tactics.length === 0 && rules.length === 0;

  return (
    <div className="panel p-5">
      <div className="mb-4 flex items-center justify-between">
        <span className="panel-title">
          <span className="icon-slot h-7 w-7 bg-fuchsia-500/10 text-fuchsia-300 ring-1 ring-fuchsia-500/20">
            <TargetIcon size={15} />
          </span>
          Tehdit Görünümü
        </span>
        <span className="font-mono text-xs text-slate-500">MITRE ATT&amp;CK</span>
      </div>

      {empty ? (
        <p className="py-8 text-center text-sm text-slate-500">Henüz sınıflandırılmış tehdit yok.</p>
      ) : (
        <div className="grid grid-cols-1 gap-x-8 gap-y-6 sm:grid-cols-2">
          <div>
            <h4 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-500">
              Taktik dağılımı
            </h4>
            <div className="space-y-2.5">
              {tactics.map(([t, v]) => (
                <Bar
                  key={t}
                  label={t}
                  value={v}
                  max={maxT}
                  tone="bg-gradient-to-r from-fuchsia-500/80 to-violet-500/70"
                />
              ))}
            </div>
          </div>
          <div>
            <h4 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-500">
              En çok tetiklenen kurallar
            </h4>
            <ul className="space-y-1.5">
              {rules.map(([r, v], i) => (
                <li key={r} className="flex items-center justify-between gap-2 text-xs">
                  <span className="flex min-w-0 items-center gap-2">
                    <span className="w-4 shrink-0 text-right font-mono text-slate-600">{i + 1}</span>
                    <span className="truncate font-mono text-slate-300">{r}</span>
                  </span>
                  <span className="shrink-0 rounded bg-white/[0.05] px-1.5 py-0.5 font-mono font-semibold tabular-nums text-slate-300">
                    {v}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
