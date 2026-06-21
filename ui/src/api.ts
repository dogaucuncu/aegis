// Aegis SOC sunucusuna REST istemcisi.
const BASE = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000";

export interface Alert {
  id: number;
  created_at: string;
  rule_id: string;
  severity: string;
  title: string;
  description: string;
  agent_id?: string | null;
  event_id?: number | null;
  status: string;
  count: number;
  last_seen?: string | null;
}

export interface AegisEvent {
  id: number;
  agent_id: string;
  event_type: string;
  timestamp: string;
  data: Record<string, unknown>;
  prev_hash?: string | null;
  hash?: string | null;
  signed?: boolean;
}

export interface Integrity {
  total_events: number;
  valid: boolean;
  broken_at_event_id: number | null;
  message: string;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path);
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  base: BASE,
  alerts: () => get<Alert[]>("/api/alerts?limit=200"),
  events: () => get<AegisEvent[]>("/api/events?limit=200"),
  integrity: () => get<Integrity>("/api/integrity/verify"),
  updateAlertStatus: (id: number, status: string) =>
    fetch(`${BASE}/api/alerts/${id}/status?status=${status}`, { method: "POST" }),
};
