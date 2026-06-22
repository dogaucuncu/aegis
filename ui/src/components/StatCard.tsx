import type { ReactNode } from "react";

interface Props {
  label: string;
  value: string | number;
  icon?: ReactNode;
  /** Tailwind text color for the icon + value, e.g. "text-sky-400" */
  tone?: string;
  hint?: string;
}

export function StatCard({ label, value, icon, tone = "text-slate-100", hint }: Props) {
  return (
    <div className="panel group p-5 transition-transform duration-200 hover:-translate-y-0.5">
      <div className="flex items-start justify-between">
        <span className="text-xs font-medium uppercase tracking-[0.08em] text-slate-400">
          {label}
        </span>
        {icon && (
          <span
            className={`icon-slot h-8 w-8 bg-white/[0.04] ring-1 ring-white/[0.06] ${tone}`}
          >
            {icon}
          </span>
        )}
      </div>
      <div className={`mt-3 font-mono text-[2rem] font-semibold leading-none tabular-nums ${tone}`}>
        {value}
      </div>
      {hint && <div className="mt-2 font-mono text-[11px] text-slate-500">{hint}</div>}
    </div>
  );
}
