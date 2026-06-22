import type { Integrity } from "../api";
import { LockIcon, AlertTriangleIcon } from "./icons";

// Log chain integrity indicator (tamper-evident log status).
export function IntegrityBadge({ integrity }: { integrity: Integrity | null }) {
  if (!integrity) {
    return (
      <div className="panel p-5">
        <span className="text-xs font-medium uppercase tracking-[0.08em] text-slate-400">
          Günlük Bütünlüğü
        </span>
        <div className="mt-3 font-mono text-sm text-slate-500">yükleniyor…</div>
      </div>
    );
  }

  const ok = integrity.valid;
  return (
    <div
      className={`panel p-5 transition-transform duration-200 hover:-translate-y-0.5 ${
        ok ? "ring-1 ring-emerald-500/20" : "ring-1 ring-red-500/30"
      }`}
    >
      <div className="flex items-start justify-between">
        <span className="text-xs font-medium uppercase tracking-[0.08em] text-slate-400">
          Günlük Bütünlüğü
        </span>
        <span
          className={`icon-slot h-8 w-8 ring-1 ${
            ok
              ? "bg-emerald-500/10 text-emerald-300 ring-emerald-400/20"
              : "bg-red-500/10 text-red-300 ring-red-400/25"
          }`}
        >
          {ok ? <LockIcon size={16} /> : <AlertTriangleIcon size={16} />}
        </span>
      </div>
      <div
        className={`mt-3 text-xl font-bold leading-none ${ok ? "text-emerald-300" : "text-red-300"}`}
      >
        {ok ? "Doğrulandı" : "Kurcalanmış!"}
      </div>
      <div className="mt-2 font-mono text-[11px] text-slate-500">
        zincirde {integrity.total_events} olay
        {!ok && integrity.broken_at_event_id != null && (
          <span className="text-red-400"> · kırılma: #{integrity.broken_at_event_id}</span>
        )}
      </div>
    </div>
  );
}
