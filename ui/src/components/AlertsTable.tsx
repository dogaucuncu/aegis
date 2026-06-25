import { useMemo, useState } from "react";
import { parseServerDate } from "../api";
import type { Alert, Triage } from "../api";
import { MitreBadge, SeverityBadge, STATUS_LABEL, STATUS_OPTIONS } from "./badges";
import { BellIcon } from "./icons";

interface Props {
  alerts: Alert[];
  onStatusChange: (id: number, status: string) => void;
  onTriage: (id: number, body: Triage) => void;
}

function fmt(ts: string) {
  return parseServerDate(ts).toLocaleTimeString();
}

export function AlertsTable({ alerts, onStatusChange, onTriage }: Props) {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return alerts.filter((a) => {
      if (severity && a.severity !== severity) return false;
      if (status && a.status !== status) return false;
      if (needle) {
        const hay = `${a.title} ${a.description} ${a.rule_id} ${a.agent_id ?? ""} ${a.technique ?? ""}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [alerts, severity, status, q]);

  const inputCls =
    "rounded-md border border-white/10 bg-white/[0.04] px-2 py-1 text-xs text-slate-200 transition-colors hover:border-white/20 focus:border-sky-400/50 focus:outline-none";

  return (
    <div className="panel overflow-hidden">
      <div className="panel-header flex-wrap gap-2">
        <span className="panel-title">
          <span className="icon-slot h-7 w-7 bg-amber-500/10 text-amber-300 ring-1 ring-amber-400/20">
            <BellIcon size={15} />
          </span>
          Uyarılar
        </span>
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Ara…"
            aria-label="Uyarılarda ara"
            className={`${inputCls} w-32`}
          />
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            aria-label="Önem filtresi"
            className={inputCls}
          >
            <option value="">Tüm önemler</option>
            <option value="high">Yüksek</option>
            <option value="medium">Orta</option>
            <option value="low">Düşük</option>
          </select>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            aria-label="Durum filtresi"
            className={inputCls}
          >
            <option value="">Tüm durumlar</option>
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {STATUS_LABEL[s]}
              </option>
            ))}
          </select>
          <span className="font-mono text-xs text-slate-500">{filtered.length} kayıt</span>
        </div>
      </div>
      <div className="max-h-[60vh] overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="table-head">
            <tr>
              <th className="px-5 py-2.5">Önem</th>
              <th className="px-4 py-2.5">Başlık</th>
              <th className="px-4 py-2.5">ATT&amp;CK</th>
              <th className="px-4 py-2.5">Ajan</th>
              <th className="px-4 py-2.5">Atanan</th>
              <th className="px-4 py-2.5">Zaman</th>
              <th className="px-4 py-2.5">Durum</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center text-slate-600">
                  Eşleşen uyarı yok.
                </td>
              </tr>
            )}
            {filtered.map((a) => (
              <tr key={a.id} className="row-hover border-t border-white/[0.04]">
                <td className="px-5 py-2.5 align-top">
                  <SeverityBadge severity={a.severity} />
                </td>
                <td className="px-4 py-2.5 align-top">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-slate-100">{a.title}</span>
                    {a.count > 1 && (
                      <span className="rounded-full bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs font-semibold text-slate-200">
                        ×{a.count}
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 text-xs text-slate-500">{a.description}</div>
                  {a.tags && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {a.tags.split(",").map((t) => t.trim()).filter(Boolean).map((t) => (
                        <span
                          key={t}
                          className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[10px] text-slate-300"
                        >
                          #{t}
                        </span>
                      ))}
                    </div>
                  )}
                </td>
                <td className="px-4 py-2.5 align-top">
                  <MitreBadge tactic={a.tactic} technique={a.technique} />
                </td>
                <td className="px-4 py-2.5 align-top text-slate-300">{a.agent_id ?? "—"}</td>
                <td className="px-4 py-2.5 align-top">
                  <input
                    defaultValue={a.assignee ?? ""}
                    placeholder="—"
                    aria-label={`${a.title} için atanan`}
                    onBlur={(e) => {
                      const v = e.target.value.trim();
                      if (v !== (a.assignee ?? "")) onTriage(a.id, { assignee: v });
                    }}
                    className={`${inputCls} w-24`}
                  />
                </td>
                <td className="px-4 py-2.5 align-top font-mono text-xs text-slate-400">
                  {fmt(a.created_at)}
                </td>
                <td className="px-4 py-2.5 align-top">
                  <select
                    value={a.status}
                    onChange={(e) => onStatusChange(a.id, e.target.value)}
                    aria-label={`${a.title} için durum`}
                    className="cursor-pointer rounded-md border border-white/10 bg-white/[0.04] px-2 py-1 text-xs text-slate-200 transition-colors hover:border-white/20 focus:border-sky-400/50"
                  >
                    {STATUS_OPTIONS.map((s) => (
                      <option key={s} value={s}>
                        {STATUS_LABEL[s]}
                      </option>
                    ))}
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
