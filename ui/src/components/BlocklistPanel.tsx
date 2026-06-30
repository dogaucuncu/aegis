import type { BlockedIP } from "../api";
import { parseServerDate } from "../api";
import { BanIcon } from "./icons";

function ago(ts?: string): string {
  if (!ts) return "";
  const secs = Math.max(0, (Date.now() - parseServerDate(ts).getTime()) / 1000);
  if (secs < 60) return "az önce";
  if (secs < 3600) return `${Math.floor(secs / 60)} dk önce`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} sa önce`;
  return `${Math.floor(secs / 86400)} gün önce`;
}

// The auto-response surface: IPs blocked by the responder (or manually), with an unblock action.
export function BlocklistPanel({
  blocked,
  onUnblock,
}: {
  blocked: BlockedIP[];
  onUnblock: (ip: string) => void;
}) {
  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">
          <span className="icon-slot h-7 w-7 bg-red-500/10 text-red-300 ring-1 ring-red-500/20">
            <BanIcon size={15} />
          </span>
          Engellenen IP&apos;ler
        </span>
        <span className="chip border-red-500/25 bg-red-500/10 text-red-300">{blocked.length} aktif</span>
      </div>

      {blocked.length === 0 ? (
        <p className="px-5 py-8 text-center text-sm leading-relaxed text-slate-500">
          Engellenen IP yok. Otomatik müdahale (<span className="font-mono text-slate-400">AEGIS_AUTO_BLOCK</span>)
          bir kuralı tetiklediğinde saldırgan IP burada belirir.
        </p>
      ) : (
        <ul className="divide-y" style={{ borderColor: "var(--border)" }}>
          {blocked.map((b) => (
            <li key={b.ip} className="row-hover flex items-center justify-between gap-3 px-5 py-2.5">
              <div className="min-w-0">
                <div className="font-mono text-sm text-slate-100">{b.ip}</div>
                <div className="mt-0.5 text-[11px] text-slate-500">
                  {b.reason === "manual" ? (
                    <span className="text-slate-400">manuel engelleme</span>
                  ) : (
                    <span className="font-mono text-slate-400">{b.rule_id ?? b.reason}</span>
                  )}
                  {b.created_at && <span className="text-slate-600"> · {ago(b.created_at)}</span>}
                </div>
              </div>
              <button
                onClick={() => onUnblock(b.ip)}
                className="shrink-0 cursor-pointer rounded-lg border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 text-xs font-medium text-slate-300 transition-colors duration-150 hover:border-red-500/30 hover:bg-red-500/10 hover:text-red-200"
              >
                Kaldır
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
