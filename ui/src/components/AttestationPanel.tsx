import type { AttestResult, Attestation } from "../api";
import { parseServerDate } from "../api";
import {
  AlertTriangleIcon,
  BanIcon,
  FingerprintIcon,
  ShieldCheckIcon,
  ShieldIcon,
} from "./icons";

function ago(ts?: string | null): string {
  if (!ts) return "";
  const secs = Math.max(0, (Date.now() - parseServerDate(ts).getTime()) / 1000);
  if (secs < 60) return "az önce";
  if (secs < 3600) return `${Math.floor(secs / 60)} dk önce`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} sa önce`;
  return `${Math.floor(secs / 86400)} gün önce`;
}

// Human-readable Turkish for the verifier's machine reason codes.
const REASONS: Record<string, string> = {
  nonce_mismatch: "replay / eski nonce",
  bad_signature: "sahte imza (yanlış anahtar)",
  no_challenge_or_stale: "challenge yok / bayat",
  pcr_digest_mismatch: "PCR digest uyuşmuyor",
  malformed_quote: "bozuk quote",
};

type Meta = {
  label: string;
  tone: string; // chip border/bg/text
  Icon: typeof ShieldCheckIcon;
};

// Every state carries an icon + text label, never colour alone (a11y: color-not-only).
function meta(result: AttestResult): Meta {
  switch (result) {
    case "pass":
      return {
        label: "Doğrulandı",
        tone: "border-emerald-500/25 bg-emerald-500/10 text-emerald-300",
        Icon: ShieldCheckIcon,
      };
    case "pcr_drift":
      return {
        label: "PCR sürüklenmesi",
        tone: "border-amber-500/25 bg-amber-500/10 text-amber-300",
        Icon: AlertTriangleIcon,
      };
    case "attestation_fail":
      return {
        label: "Attestation hatası",
        tone: "border-red-500/25 bg-red-500/10 text-red-300",
        Icon: BanIcon,
      };
    default:
      return {
        label: "Beklemede",
        tone: "border-white/[0.08] bg-white/[0.04] text-slate-400",
        Icon: ShieldIcon,
      };
  }
}

function SummaryPill({ n, label, tone }: { n: number; label: string; tone: string }) {
  return (
    <span className={`chip ${tone}`}>
      <span className="font-mono font-semibold tabular-nums">{n}</span>
      {label}
    </span>
  );
}

// Endpoint Integrity: per-endpoint TPM 2.0 measured-boot attestation verdict (Milestone 7).
export function AttestationPanel({ endpoints }: { endpoints: Attestation[] }) {
  const ok = endpoints.filter((e) => e.last_result === "pass").length;
  const drift = endpoints.filter((e) => e.last_result === "pcr_drift").length;
  const fail = endpoints.filter((e) => e.last_result === "attestation_fail").length;

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">
          <span className="icon-slot h-7 w-7 bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-500/20">
            <FingerprintIcon size={15} />
          </span>
          Uç Nokta Bütünlüğü
        </span>
        <span className="font-mono text-xs text-slate-500">TPM 2.0</span>
      </div>

      {endpoints.length === 0 ? (
        <p className="px-5 py-8 text-center text-sm leading-relaxed text-slate-500">
          Kayıtlı uç nokta yok. Measured-boot attestation için{" "}
          <span className="font-mono text-slate-400">scripts/tpm_replay_attack.py</span> çalıştırın
          veya ajanda <span className="font-mono text-slate-400">tpm_attest: true</span> ayarlayın.
        </p>
      ) : (
        <>
          <div className="flex flex-wrap gap-2 border-b px-5 py-3" style={{ borderColor: "var(--border)" }}>
            <SummaryPill n={ok} label="doğrulandı" tone="border-emerald-500/25 bg-emerald-500/10 text-emerald-300" />
            <SummaryPill n={drift} label="sürüklenme" tone="border-amber-500/25 bg-amber-500/10 text-amber-300" />
            <SummaryPill n={fail} label="hata" tone="border-red-500/25 bg-red-500/10 text-red-300" />
          </div>

          <ul className="divide-y" style={{ borderColor: "var(--border)" }}>
            {endpoints.map((e) => {
              const m = meta(e.last_result);
              return (
                <li key={e.agent_id} className="row-hover flex items-start justify-between gap-3 px-5 py-3">
                  <div className="min-w-0">
                    <div className="font-mono text-sm text-slate-100">{e.agent_id}</div>
                    <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-slate-500">
                      <span>
                        <span className="tabular-nums text-slate-400">{e.pcr_count}</span> PCR
                        <span className="text-slate-600"> ({e.selection.join(", ")})</span>
                      </span>
                      {e.last_result === "pcr_drift" && e.drifted_pcrs.length > 0 && (
                        <span className="flex items-center gap-1">
                          <span className="text-slate-600">·</span>
                          <span className="text-amber-300/80">değişen:</span>
                          {e.drifted_pcrs.map((p) => (
                            <span
                              key={p}
                              className="rounded bg-amber-500/10 px-1.5 py-0.5 font-mono font-semibold tabular-nums text-amber-300 ring-1 ring-inset ring-amber-500/20"
                            >
                              PCR{p}
                            </span>
                          ))}
                        </span>
                      )}
                      {e.last_result === "attestation_fail" && e.last_reason && (
                        <span className="text-red-300/80">· {REASONS[e.last_reason] ?? e.last_reason}</span>
                      )}
                      {e.last_seen && <span className="text-slate-600">· {ago(e.last_seen)}</span>}
                    </div>
                  </div>
                  <span className={`chip shrink-0 ${m.tone}`}>
                    <m.Icon size={13} />
                    {m.label}
                  </span>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </div>
  );
}
