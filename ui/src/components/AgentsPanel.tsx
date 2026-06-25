import { parseServerDate } from "../api";
import type { Agent } from "../api";
import { ServerIcon } from "./icons";

// An agent is considered "online" if its last heartbeat is within this window.
const ONLINE_WINDOW_MS = 60_000;

function sinceText(ts: string): string {
  const secs = Math.max(0, (Date.now() - parseServerDate(ts).getTime()) / 1000);
  if (secs < 60) return `${Math.floor(secs)} sn önce`;
  if (secs < 3600) return `${Math.floor(secs / 60)} dk önce`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} sa önce`;
  return `${Math.floor(secs / 86400)} gün önce`;
}

export function AgentsPanel({ agents }: { agents: Agent[] }) {
  const now = Date.now();
  return (
    <div className="panel overflow-hidden">
      <div className="panel-header">
        <span className="panel-title">
          <span className="icon-slot h-7 w-7 bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-400/20">
            <ServerIcon size={15} />
          </span>
          Ajanlar
        </span>
        <span className="font-mono text-xs text-slate-500">{agents.length} kayıt</span>
      </div>
      <div className="max-h-[40vh] overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="table-head">
            <tr>
              <th className="px-5 py-2.5">Ajan</th>
              <th className="px-4 py-2.5">Durum</th>
              <th className="px-4 py-2.5">Son görülme</th>
              <th className="px-4 py-2.5 text-right">Olay</th>
            </tr>
          </thead>
          <tbody>
            {agents.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-10 text-center text-slate-600">
                  Henüz ajan telemetri göndermedi.
                </td>
              </tr>
            )}
            {agents.map((a) => {
              const online = now - parseServerDate(a.last_seen).getTime() < ONLINE_WINDOW_MS;
              return (
                <tr key={a.agent_id} className="row-hover border-t border-white/[0.04]">
                  <td className="px-5 py-2.5 font-medium text-slate-100">{a.agent_id}</td>
                  <td className="px-4 py-2.5">
                    <span className="inline-flex items-center gap-1.5 text-xs">
                      <span
                        className={`inline-flex h-2 w-2 rounded-full ${
                          online ? "bg-emerald-400" : "bg-slate-600"
                        }`}
                        aria-hidden="true"
                      />
                      <span className={online ? "text-emerald-300" : "text-slate-500"}>
                        {online ? "çevrimiçi" : "çevrimdışı"}
                      </span>
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-slate-400">
                    {sinceText(a.last_seen)}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono text-xs text-slate-300">
                    {a.event_count}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
