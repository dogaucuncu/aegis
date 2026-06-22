// Severity + status pills. The underlying value stays English (API contract),
// only the visible label is Turkish, kept in one place so it reads consistently.

const SEVERITY_STYLES: Record<string, string> = {
  high: "bg-red-500/15 text-red-300 border-red-500/30",
  medium: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  low: "bg-slate-500/15 text-slate-300 border-slate-500/30",
};

export const SEVERITY_LABEL: Record<string, string> = {
  high: "Yüksek",
  medium: "Orta",
  low: "Düşük",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.low;
  return (
    <span
      className={`inline-block rounded-full border px-2 py-0.5 text-xs font-semibold tracking-wide ${cls}`}
    >
      {SEVERITY_LABEL[severity] ?? severity}
    </span>
  );
}

const STATUS_STYLES: Record<string, string> = {
  open: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
  triaged: "bg-violet-500/15 text-violet-300 border-violet-500/30",
  closed: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
};

export const STATUS_LABEL: Record<string, string> = {
  open: "Açık",
  triaged: "İncelemede",
  closed: "Kapandı",
};

export function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_STYLES[status] ?? STATUS_STYLES.open;
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${cls}`}>
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}
