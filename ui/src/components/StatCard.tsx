interface Props {
  label: string;
  value: string | number;
  accent?: string; // tailwind text rengi, ör. "text-red-400"
  hint?: string;
}

export function StatCard({ label, value, accent = "text-slate-100", hint }: Props) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</div>
      <div className={`mt-1 text-3xl font-bold tabular-nums ${accent}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}
