/**
 * User settings, persisted in chrome.storage.local. Weights and thresholds
 * for the scoring engine are user-configurable (M8); defaults live in
 * core/scoring.ts.
 */
import { DEFAULT_THRESHOLDS, DEFAULT_WEIGHTS, type SignalId, type Thresholds } from '../core/scoring';

/** Per-feed configuration for the URL-list threat feeds (N1). */
export interface FeedConfig {
  enabled: boolean;
  /** API key / app key where the feed supports one. */
  apiKey: string;
  /** Override the feed URL (used by the generic enterprise adapter). */
  url: string;
}

export interface Settings {
  weights: Record<SignalId, number>;
  thresholds: Thresholds;
  /** Store only SHA-256 hashes of domains in the audit log. */
  privacyHashDomains: boolean;
  /** Audit-log retention in days (0 = keep forever). */
  logRetentionDays: number;
  /** Google Safe Browsing API key (Update API v4). Empty = feed disabled. */
  safeBrowsingApiKey: string;
  /** URL-list threat feeds, all disabled by default (bandwidth + privacy). */
  feeds: {
    phishtank: FeedConfig;
    openphish: FeedConfig;
    urlhaus: FeedConfig;
    /** Generic enterprise feed (MISP export / custom REST returning a URL list). */
    custom: FeedConfig;
  };
  /** Domain-age lookups via cached RDAP, weighted into the risk score (N2). */
  rdapDomainAge: boolean;
  /** Warn when a password was previously used on a different origin (N10). */
  passwordReuseGuard: boolean;
  /** Enable webmail email inspection. */
  emailInspection: boolean;
  /** Show non-blocking banner on Suspicious pages. */
  suspiciousBanner: boolean;
}

const FEED_OFF: FeedConfig = { enabled: false, apiKey: '', url: '' };

export const DEFAULT_SETTINGS: Settings = {
  weights: DEFAULT_WEIGHTS,
  thresholds: DEFAULT_THRESHOLDS,
  privacyHashDomains: false,
  logRetentionDays: 365,
  safeBrowsingApiKey: '',
  feeds: {
    phishtank: { ...FEED_OFF },
    openphish: { ...FEED_OFF },
    urlhaus: { ...FEED_OFF },
    custom: { ...FEED_OFF },
  },
  rdapDomainAge: true,
  passwordReuseGuard: true,
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
    feeds: {
      phishtank: { ...FEED_OFF, ...stored?.feeds?.phishtank },
      openphish: { ...FEED_OFF, ...stored?.feeds?.openphish },
      urlhaus: { ...FEED_OFF, ...stored?.feeds?.urlhaus },
      custom: { ...FEED_OFF, ...stored?.feeds?.custom },
    },
  };
}

export async function updateSettings(patch: Partial<Settings>): Promise<Settings> {
  const current = await getSettings();
  const next = { ...current, ...patch };
  await chrome.storage.local.set({ [KEY]: next });
  return next;
}
