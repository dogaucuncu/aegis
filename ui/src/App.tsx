import { useCallback, useRef, useState } from "react";
import { api } from "./api";
import type { Alert, AegisEvent, Agent, Integrity, Triage } from "./api";
import { usePolling } from "./hooks/usePolling";
import { useSSE } from "./hooks/useSSE";
import { StatCard } from "./components/StatCard";
import { IntegrityBadge } from "./components/IntegrityBadge";
import { AlertsTable } from "./components/AlertsTable";
import { EventsTable } from "./components/EventsTable";
import { AgentsPanel } from "./components/AgentsPanel";
import { ScanPanel } from "./components/ScanPanel";
import { MlPanel } from "./components/MlPanel";
import { SeverityChart } from "./components/SeverityChart";
import {
  ShieldCheckIcon,
  ActivityIcon,
  AlertTriangleIcon,
  LayersIcon,
  BoltIcon,
} from "./components/icons";

function clock(d: Date) {
  return d.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export default function App() {
  // Since SSE drives live updates, polling remains as a slow fallback.
  const alertsQ = usePolling<Alert[]>(api.alerts, 15000);
  const eventsQ = usePolling<AegisEvent[]>(api.events, 15000);
  const agentsQ = usePolling<Agent[]>(api.agents, 15000);
  const integrityQ = usePolling<Integrity>(api.integrity, 15000);

  const [liveCount, setLiveCount] = useState(0);
  const [lastUpdate, setLastUpdate] = useState(() => new Date());
  const refreshTimer = useRef<number | null>(null);

  // SSE: when a new alert arrives, refresh all data (debounced) + increment the live counter.
  useSSE(`${api.base}/api/stream`, "alert", () => {
    setLiveCount((c) => c + 1);
    if (refreshTimer.current != null) return;
    refreshTimer.current = window.setTimeout(() => {
      refreshTimer.current = null;
      alertsQ.refresh();
      eventsQ.refresh();
      agentsQ.refresh();
      integrityQ.refresh();
      setLastUpdate(new Date());
    }, 400);
  });

  const alerts = alertsQ.data ?? [];
  const events = eventsQ.data ?? [];
  const agents = agentsQ.data ?? [];
  const highCount = alerts.filter((a) => a.severity === "high").length;
  const openCount = alerts.filter((a) => a.status === "open").length;
  const connected = !alertsQ.error;

  const handleStatusChange = useCallback(
    async (id: number, status: string) => {
      await api.updateAlertStatus(id, status);
      alertsQ.refresh();
    },
    [alertsQ],
  );

  const handleTriage = useCallback(
    async (id: number, body: Triage) => {
      await api.updateAlertTriage(id, body);
      alertsQ.refresh();
    },
    [alertsQ],
  );

  return (
    <div className="mx-auto max-w-7xl px-5 py-7 sm:px-6">
      {/* Top bar */}
      <header className="mb-5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="relative grid h-11 w-11 place-items-center rounded-xl bg-gradient-to-br from-sky-500/25 to-indigo-500/10 text-sky-300 ring-1 ring-inset ring-sky-400/30">
            <span className="absolute inset-0 rounded-xl bg-sky-400/10 blur-md" aria-hidden="true" />
            <ShieldCheckIcon size={22} className="relative" />
          </div>
          <div>
            <h1 className="text-[1.35rem] font-bold leading-tight tracking-tight text-slate-50">
              Aegis <span className="text-sky-400">SOC</span>
            </h1>
            <p className="text-xs text-slate-500">Mini Güvenlik Operasyon Merkezi</p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 text-sm">
          {liveCount > 0 && (
            <span className="chip border-sky-500/30 bg-sky-500/10 text-sky-300">
              <BoltIcon size={13} />
              canlı · {liveCount} yeni
            </span>
          )}
          <div
            className="flex items-center gap-2 rounded-full border border-white/[0.07] bg-white/[0.03] px-3 py-1.5"
            role="status"
            aria-live="polite"
          >
            <span className="relative flex h-2.5 w-2.5" aria-hidden="true">
              {connected && (
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/70" />
              )}
              <span
                className={`relative inline-flex h-2.5 w-2.5 rounded-full ${
                  connected ? "bg-emerald-400" : "bg-red-500"
                }`}
              />
            </span>
            <span className="text-xs text-slate-400">
              {connected ? "Sunucu bağlı" : "Sunucuya erişilemiyor"}
            </span>
            {connected && (
              <span className="hidden font-mono text-[11px] text-slate-600 sm:inline">
                · {clock(lastUpdate)}
              </span>
            )}
          </div>
        </div>
      </header>

      {/* Hairline accent under the header */}
      <div
        className="mb-6 h-px w-full bg-gradient-to-r from-sky-400/30 via-white/[0.06] to-transparent"
        aria-hidden="true"
      />

      {alertsQ.error && (
        <div className="mb-5 flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          <AlertTriangleIcon size={17} className="mt-0.5 shrink-0 text-red-300" />
          <div>
            Sunucuya bağlanılamadı (<span className="font-mono">{api.base}</span>). Sunucunun
            çalıştığından emin olun:
            <code className="ml-1 rounded bg-black/30 px-1.5 py-0.5 font-mono text-xs text-red-100">
              uvicorn app.main:app --port 8000
            </code>
          </div>
        </div>
      )}

      {/* Stat cards */}
      <section className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="animate-fade-in-up" style={{ animationDelay: "0ms" }}>
          <StatCard
            label="Toplam Uyarı"
            value={alerts.length}
            icon={<ActivityIcon size={16} />}
            tone="text-slate-100"
          />
        </div>
        <div className="animate-fade-in-up" style={{ animationDelay: "60ms" }}>
          <StatCard
            label="Yüksek Önem"
            value={highCount}
            icon={<AlertTriangleIcon size={16} />}
            tone="text-red-400"
            hint="önem = yüksek"
          />
        </div>
        <div className="animate-fade-in-up" style={{ animationDelay: "120ms" }}>
          <StatCard
            label="Açık Uyarılar"
            value={openCount}
            icon={<LayersIcon size={16} />}
            tone="text-sky-400"
            hint="durum = açık"
          />
        </div>
        <div className="animate-fade-in-up" style={{ animationDelay: "180ms" }}>
          <IntegrityBadge integrity={integrityQ.data} />
        </div>
      </section>

      {/* Severity distribution */}
      <div className="mb-6 animate-fade-in-up" style={{ animationDelay: "220ms" }}>
        <SeverityChart alerts={alerts} />
      </div>

      {/* Red Team + ML panels */}
      <div className="mb-6 grid grid-cols-1 gap-6 xl:grid-cols-2">
        <div className="animate-fade-in-up" style={{ animationDelay: "260ms" }}>
          <ScanPanel alerts={alerts} events={events} />
        </div>
        <div className="animate-fade-in-up" style={{ animationDelay: "300ms" }}>
          <MlPanel alerts={alerts} />
        </div>
      </div>

      {/* Agent inventory */}
      <div className="mb-6 animate-fade-in-up" style={{ animationDelay: "320ms" }}>
        <AgentsPanel agents={agents} />
      </div>

      {/* Tables */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <div className="animate-fade-in-up" style={{ animationDelay: "340ms" }}>
          <AlertsTable
            alerts={alerts}
            onStatusChange={handleStatusChange}
            onTriage={handleTriage}
          />
        </div>
        <div className="animate-fade-in-up" style={{ animationDelay: "380ms" }}>
          <EventsTable events={events} />
        </div>
      </div>

      <footer className="mt-9 flex flex-wrap items-center justify-center gap-x-2 gap-y-1 border-t border-white/[0.05] pt-5 text-center text-xs text-slate-600">
        <span className="font-semibold text-slate-500">Aegis mini-SOC</span>
        <span className="text-slate-700">·</span>
        <span>Mavi + Kırmızı + ML + Kripto</span>
        <span className="text-slate-700">·</span>
        <span className="font-mono">
          {events.length} olay, {alerts.length} uyarı izleniyor
        </span>
      </footer>
    </div>
  );
}
