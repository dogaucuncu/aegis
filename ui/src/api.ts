// REST client for the Aegis SOC server.
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
  assignee?: string | null;
  note?: string | null;
  tags?: string | null;
  tactic?: string | null;
  technique?: string | null;
}

export interface Agent {
  agent_id: string;
  first_seen: string;
  last_seen: string;
  version?: string | null;
  event_count: number;
}

export interface Triage {
  assignee?: string;
  note?: string;
  tags?: string;
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

export interface Stats {
  alerts_total: number;
  alerts_open: number;
  events_total: number;
  blocked_ips: number;
  by_severity: Record<string, number>;
  by_tactic: Record<string, number>;
  by_rule: Record<string, number>;
  events_by_type: Record<string, number>;
  top_agents: Record<string, number>;
}

export interface BlockedIP {
  ip: string;
  reason?: string | null;
  rule_id?: string | null;
  created_at: string;
}

// Per-endpoint TPM 2.0 measured-boot attestation status (Milestone 7).
export type AttestResult = "pass" | "pcr_drift" | "attestation_fail" | null;

export interface Attestation {
  agent_id: string;
  enrolled_at: string;
  pcr_count: number;
  selection: number[];
  last_result: AttestResult;
  last_reason: string;
  drifted_pcrs: number[];
  source_ip?: string | null;
  last_seen?: string | null;
}

// Server timestamps are naive UTC (no tz suffix); parse them as UTC, not browser-local.
export function parseServerDate(ts: string): Date {
  return new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(ts) ? ts : ts + "Z");
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
  agents: () => get<Agent[]>("/api/agents"),
  integrity: () => get<Integrity>("/api/integrity/verify"),
  stats: () => get<Stats>("/api/stats"),
  blocklist: () => get<BlockedIP[]>("/api/blocklist"),
  attestation: () => get<Attestation[]>("/api/attest/status"),
  unblockIp: (ip: string) =>
    fetch(`${BASE}/api/blocklist/${encodeURIComponent(ip)}`, { method: "DELETE" }),
  updateAlertStatus: (id: number, status: string) =>
    fetch(`${BASE}/api/alerts/${id}/status?status=${status}`, { method: "POST" }),
  updateAlertTriage: (id: number, body: Triage) =>
    fetch(`${BASE}/api/alerts/${id}/triage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
};
