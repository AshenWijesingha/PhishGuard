/**
 * Domain-age lookup via RDAP (N2). Freshly registered domains are a strong
 * phishing signal — most phishing domains are used within days of
 * registration.
 *
 * Privacy/performance: the caller only invokes this when a page already
 * shows some suspicion (so we don't reveal ordinary browsing to RDAP
 * servers), results are cached for 30 days, and failures (offline,
 * unsupported TLD, rate limit) resolve to null and add no signal.
 */

const CACHE_KEY = 'pg_rdap_cache';
const CACHE_TTL_MS = 30 * 86400_000;
const NEGATIVE_TTL_MS = 86400_000; // retry failed lookups daily
const MAX_CACHE_ENTRIES = 2000;

interface RdapCacheEntry {
  /** Registration epoch ms, or null if the lookup failed / had no date. */
  registered: number | null;
  fetched: number;
}

type RdapCache = Record<string, RdapCacheEntry>;

/**
 * Returns the age of a registrable domain in days, or null when unknown.
 */
export async function getDomainAgeDays(registrableDomain: string, now = Date.now()): Promise<number | null> {
  const domain = registrableDomain.toLowerCase();
  if (!domain || !domain.includes('.')) return null;

  const cache = ((await chrome.storage.local.get(CACHE_KEY))[CACHE_KEY] as RdapCache | undefined) ?? {};
  const entry = cache[domain];
  if (entry) {
    const ttl = entry.registered === null ? NEGATIVE_TTL_MS : CACHE_TTL_MS;
    if (now - entry.fetched < ttl) {
      return entry.registered === null ? null : Math.floor((now - entry.registered) / 86400_000);
    }
  }

  const registered = await fetchRegistrationDate(domain);
  cache[domain] = { registered, fetched: now };
  // Bound the cache size (drop oldest entries).
  const keys = Object.keys(cache);
  if (keys.length > MAX_CACHE_ENTRIES) {
    keys
      .sort((a, b) => cache[a]!.fetched - cache[b]!.fetched)
      .slice(0, keys.length - MAX_CACHE_ENTRIES)
      .forEach((k) => delete cache[k]);
  }
  await chrome.storage.local.set({ [CACHE_KEY]: cache });
  return registered === null ? null : Math.floor((now - registered) / 86400_000);
}

async function fetchRegistrationDate(domain: string): Promise<number | null> {
  try {
    // rdap.org redirects to the authoritative registry RDAP server.
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { accept: 'application/rdap+json' },
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { events?: { eventAction?: string; eventDate?: string }[] };
    const reg = body.events?.find((e) => e.eventAction === 'registration')?.eventDate;
    if (!reg) return null;
    const ts = Date.parse(reg);
    return Number.isFinite(ts) ? ts : null;
  } catch {
    return null;
  }
}
