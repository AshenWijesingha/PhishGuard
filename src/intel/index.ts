/**
 * Threat-intel orchestration: runs every enabled adapter against a URL,
 * with a short-lived per-URL verdict cache so repeated checks of the same
 * page (navigation + form submit + popup) cost one lookup.
 *
 * Adapters (in priority order): Google Safe Browsing (hash-prefix,
 * k-anonymity), then the local URL-list feeds — PhishTank, OpenPhish,
 * URLhaus, and the generic enterprise feed (all matched offline).
 */
import type { TiAdapter, TiVerdict } from './adapter';
import { SafeBrowsingAdapter } from './safebrowsing';
import { FEED_SPECS, UrlFeedAdapter } from './feeds';
import { getSettings } from '../storage/settings';

const adapters: TiAdapter[] = [
  new SafeBrowsingAdapter(async () => (await getSettings()).safeBrowsingApiKey),
  new UrlFeedAdapter(FEED_SPECS.phishtank!, async () => (await getSettings()).feeds.phishtank),
  new UrlFeedAdapter(FEED_SPECS.openphish!, async () => (await getSettings()).feeds.openphish),
  new UrlFeedAdapter(FEED_SPECS.urlhaus!, async () => (await getSettings()).feeds.urlhaus),
  new UrlFeedAdapter(FEED_SPECS.custom!, async () => (await getSettings()).feeds.custom),
];

const verdictCache = new Map<string, { verdict: TiVerdict | null; expires: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000;

export async function checkThreatIntel(url: string): Promise<TiVerdict | null> {
  const cached = verdictCache.get(url);
  if (cached && cached.expires > Date.now()) return cached.verdict;

  let verdict: TiVerdict | null = null;
  for (const adapter of adapters) {
    try {
      if (!(await adapter.isEnabled())) continue;
      verdict = await adapter.checkUrl(url);
      if (verdict) break;
    } catch {
      // A failing feed must never break detection.
    }
  }
  if (verdictCache.size > 500) verdictCache.clear();
  verdictCache.set(url, { verdict, expires: Date.now() + CACHE_TTL_MS });
  return verdict;
}

export async function refreshThreatIntel(): Promise<void> {
  for (const adapter of adapters) {
    try {
      if (await adapter.isEnabled()) await adapter.refresh();
    } catch {
      /* keep going */
    }
  }
}

export { getDomainAgeDays } from './rdap';
