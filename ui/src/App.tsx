import { useCallback, useRef, useState } from "react";
import { api } from "./api";
import type { Alert, AegisEvent, Integrity } from "./api";
import { usePolling } from "./hooks/usePolling";
import { useSSE } from "./hooks/useSSE";
import { StatCard } from "./components/StatCard";
import { IntegrityBadge } from "./components/IntegrityBadge";
import { AlertsTable } from "./components/AlertsTable";
import { EventsTable } from "./components/EventsTable";
import { ScanPanel } from "./components/ScanPanel";
import { MlPanel } from "./components/MlPanel";
import { SeverityChart } from "./components/SeverityChart";

export default function App() {
  // SSE canlı güncellemeleri sürdüğünden polling yavaş bir yedek (fallback) olarak kalır.
  const alertsQ = usePolling<Alert[]>(api.alerts, 15000);
  const eventsQ = usePolling<AegisEvent[]>(api.events, 15000);
  const integrityQ = usePolling<Integrity>(api.integrity, 15000);

  const [liveCount, setLiveCount] = useState(0);
  const refreshTimer = useRef<number | null>(null);

  // SSE: yeni alarm geldiğinde (debounced) tüm verileri tazele + canlı sayacı artır.
  useSSE(`${api.base}/api/stream`, "alert", () => {
    setLiveCount((c) => c + 1);
    if (refreshTimer.current != null) return;
    refreshTimer.current = window.setTimeout(() => {
      refreshTimer.current = null;
      alertsQ.refresh();
      eventsQ.refresh();
      integrityQ.refresh();
    }, 400);
  });

  const alerts = alertsQ.data ?? [];
  const events = eventsQ.data ?? [];
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

  return (
    <div className="mx-auto max-w-7xl px-6 py-6">
      {/* Üst bar */}
      <header className="mb-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/20 text-xl">
            🛡️
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">Aegis SOC</h1>
            <p className="text-xs text-slate-500">Mini Security Operations Center</p>
          </div>
        </div>
        <div className="flex items-center gap-3 text-sm">
          {liveCount > 0 && (
            <span className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-2 py-0.5 text-xs font-medium text-cyan-300">
              ⚡ canlı · {liveCount} yeni
            </span>
          )}
          <div className="flex items-center gap-2">
            <span
              className={`h-2.5 w-2.5 rounded-full ${connected ? "bg-emerald-400 animate-pulse" : "bg-red-500"}`}
            />
            <span className="text-slate-400">
              {connected ? "Sunucu bağlı (SSE)" : "Sunucuya ulaşılamıyor"}
            </span>
          </div>
        </div>
      </header>

      {alertsQ.error && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          Sunucuya bağlanılamadı ({api.base}). Sunucunun çalıştığından emin ol:
          <code className="ml-1">uvicorn app.main:app --port 8000</code>
        </div>
      )}

      {/* İstatistik kartları */}
      <section className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Toplam Alarm" value={alerts.length} />
        <StatCard label="Yüksek Önem" value={highCount} accent="text-red-400" hint="severity=high" />
        <StatCard label="Açık Alarm" value={openCount} accent="text-cyan-400" hint="status=open" />
        <IntegrityBadge integrity={integrityQ.data} />
      </section>

      {/* Önem dağılımı */}
      <div className="mb-6">
        <SeverityChart alerts={alerts} />
      </div>

      {/* Red Team + ML panelleri */}
      <div className="mb-6 grid grid-cols-1 gap-6 xl:grid-cols-2">
        <ScanPanel alerts={alerts} events={events} />
        <MlPanel alerts={alerts} />
      </div>

      {/* Tablolar */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <AlertsTable alerts={alerts} onStatusChange={handleStatusChange} />
        <EventsTable events={events} />
      </div>

      <footer className="mt-8 text-center text-xs text-slate-600">
        Aegis mini-SOC · Blue + Red + ML + Kripto · {events.length} olay, {alerts.length} alarm izleniyor
      </footer>
    </div>
  );
}
