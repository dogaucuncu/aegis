import type { Integrity } from "../api";

// Log zinciri bütünlüğü göstergesi (tamper-evident log durumu).
export function IntegrityBadge({ integrity }: { integrity: Integrity | null }) {
  if (!integrity) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="text-xs uppercase tracking-wider text-slate-400">Log Bütünlüğü</div>
        <div className="mt-1 text-slate-500">yükleniyor…</div>
      </div>
    );
  }

  const ok = integrity.valid;
  return (
    <div
      className={`rounded-xl border p-4 ${
        ok ? "border-emerald-500/30 bg-emerald-500/10" : "border-red-500/40 bg-red-500/10"
      }`}
    >
      <div className="text-xs uppercase tracking-wider text-slate-400">Log Bütünlüğü</div>
      <div className={`mt-1 flex items-center gap-2 text-xl font-bold ${ok ? "text-emerald-300" : "text-red-300"}`}>
        <span>{ok ? "🔒 Doğrulandı" : "⚠️ Kurcalama!"}</span>
      </div>
      <div className="mt-1 text-xs text-slate-400">
        {integrity.total_events} olay zincirde
        {!ok && integrity.broken_at_event_id != null && (
          <> · kırılma: event #{integrity.broken_at_event_id}</>
        )}
      </div>
    </div>
  );
}
