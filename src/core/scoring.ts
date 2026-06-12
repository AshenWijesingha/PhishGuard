/**
 * Weighted risk-scoring engine.
 *
 * Detection modules emit Signals; this module sums their weights and maps
 * the total onto one of four verdict tiers. Weights and thresholds are
 * configurable (storage/settings.ts) — the values here are the defaults.
 */

export type Verdict = 'safe' | 'suspicious' | 'high_risk' | 'malicious';

export type SignalId =
  // URL heuristics
  | 'homoglyph'
  | 'punycode'
  | 'typosquat'
  | 'brand_in_subdomain'
  | 'excessive_subdomains'
  | 'ip_literal_host'
  | 'userinfo_in_url'
  | 'suspicious_tld'
  | 'url_shortener'
  | 'insecure_http'
  // Form signals
  | 'cross_origin_action'
  | 'http_action_from_https'
  | 'action_to_ip'
  | 'action_to_shortener'
  | 'sensitive_form_on_suspicious_page'
  // Content heuristics
  | 'urgency_language'
  | 'credential_solicitation'
  | 'payment_lure'
  | 'brand_offbrand_mismatch'
  | 'login_form_no_https'
  // Email signals
  | 'display_name_mismatch'
  | 'reply_to_divergence'
  | 'link_text_href_mismatch'
  | 'suspicious_attachment_name'
  // Threat intel / lists
  | 'threat_intel_hit'
  | 'local_blocklist_hit'
  | 'local_allowlist_hit';

export interface Signal {
  id: SignalId;
  /** Plain-language explanation shown to the user. */
  reason: string;
  /** Optional weight override; otherwise the configured weight applies. */
  weight?: number;
  /** Supporting detail (offending domain, matched word, …). */
  detail?: string;
}

export const DEFAULT_WEIGHTS: Record<SignalId, number> = {
  homoglyph: 45,
  punycode: 25,
  typosquat: 40,
  brand_in_subdomain: 40,
  excessive_subdomains: 15,
  ip_literal_host: 25,
  userinfo_in_url: 35,
  suspicious_tld: 10,
  url_shortener: 10,
  insecure_http: 10,
  cross_origin_action: 30,
  http_action_from_https: 35,
  action_to_ip: 35,
  action_to_shortener: 30,
  sensitive_form_on_suspicious_page: 20,
  urgency_language: 12,
  credential_solicitation: 15,
  payment_lure: 12,
  brand_offbrand_mismatch: 35,
  login_form_no_https: 25,
  display_name_mismatch: 30,
  reply_to_divergence: 20,
  link_text_href_mismatch: 30,
  suspicious_attachment_name: 15,
  threat_intel_hit: 1000,
  local_blocklist_hit: 1000,
  local_allowlist_hit: -1000,
};

export interface Thresholds {
  /** score >= suspicious → Suspicious */
  suspicious: number;
  /** score >= highRisk → High Risk */
  highRisk: number;
  /** score >= malicious → Confirmed Malicious (TI/blocklist hits land here) */
  malicious: number;
}

export const DEFAULT_THRESHOLDS: Thresholds = {
  suspicious: 25,
  highRisk: 55,
  malicious: 1000,
};

export interface VerdictResult {
  verdict: Verdict;
  score: number;
  signals: Signal[];
}

export function scoreSignals(
  signals: Signal[],
  weights: Record<SignalId, number> = DEFAULT_WEIGHTS,
  thresholds: Thresholds = DEFAULT_THRESHOLDS,
): VerdictResult {
  let score = 0;
  for (const s of signals) {
    score += s.weight ?? weights[s.id] ?? 0;
  }
  // An explicit allowlist hit pins the verdict to safe regardless of score.
  if (signals.some((s) => s.id === 'local_allowlist_hit')) {
    return { verdict: 'safe', score: 0, signals };
  }
  let verdict: Verdict = 'safe';
  if (score >= thresholds.malicious) verdict = 'malicious';
  else if (score >= thresholds.highRisk) verdict = 'high_risk';
  else if (score >= thresholds.suspicious) verdict = 'suspicious';
  return { verdict, score, signals };
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  safe: 'Safe',
  suspicious: 'Suspicious',
  high_risk: 'High Risk',
  malicious: 'Confirmed Malicious',
};
