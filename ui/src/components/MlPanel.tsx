import type { Alert } from "../api";
import { CpuIcon } from "./icons";

// ML view: NIDS anomaly + phishing detections (rule_id "ml-*").
export function MlPanel({ alerts }: { alerts: Alert[] }) {
  const ml = alerts.filter((a) => a.rule_id.startsWith("ml-"));

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">
          <span className="icon-slot h-7 w-7 bg-violet-500/10 text-violet-300 ring-1 ring-violet-400/20">
            <CpuIcon size={15} />
          </span>
          ML Tespitleri
        </span>
        <span className="font-mono text-xs text-slate-500">{ml.length} kayıt</span>
      </div>
      <ul className="max-h-72 divide-y divide-white/[0.04] overflow-auto">
        {ml.length === 0 && (
          <li className="px-5 py-10 text-center text-sm text-slate-600">ML tespiti yok</li>
        )}
        {ml.map((a) => (
          <li key={a.id} className="row-hover px-5 py-2.5">
            <div className="text-sm font-medium text-violet-200">{a.title}</div>
            <div className="font-mono text-xs text-slate-500">{a.description}</div>
          </li>
        ))}
      </ul>
    </div>
  );
}
