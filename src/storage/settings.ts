/**
 * User settings, persisted in chrome.storage.local. Weights and thresholds
 * for the scoring engine are user-configurable (M8); defaults live in
 * core/scoring.ts.
 */
import { DEFAULT_THRESHOLDS, DEFAULT_WEIGHTS, type SignalId, type Thresholds } from '../core/scoring';

export interface Settings {
  weights: Record<SignalId, number>;
  thresholds: Thresholds;
  /** Store only SHA-256 hashes of domains in the audit log. */
  privacyHashDomains: boolean;
  /** Audit-log retention in days (0 = keep forever). */
  logRetentionDays: number;
  /** Google Safe Browsing API key (Update API v4). Empty = feed disabled. */
  safeBrowsingApiKey: string;
  /** Enable webmail email inspection. */
  emailInspection: boolean;
  /** Show non-blocking banner on Suspicious pages. */
  suspiciousBanner: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  weights: DEFAULT_WEIGHTS,
  thresholds: DEFAULT_THRESHOLDS,
  privacyHashDomains: false,
  logRetentionDays: 365,
  safeBrowsingApiKey: '',
  emailInspection: true,
  suspiciousBanner: true,
};

const KEY = 'pg_settings';

export async function getSettings(): Promise<Settings> {
  const stored = (await chrome.storage.local.get(KEY))[KEY] as Partial<Settings> | undefined;
  return {
    ...DEFAULT_SETTINGS,
    ...stored,
    weights: { ...DEFAULT_WEIGHTS, ...stored?.weights },
    thresholds: { ...DEFAULT_THRESHOLDS, ...stored?.thresholds },
  };
}

export async function updateSettings(patch: Partial<Settings>): Promise<Settings> {
  const current = await getSettings();
  const next = { ...current, ...patch };
  await chrome.storage.local.set({ [KEY]: next });
  return next;
}
