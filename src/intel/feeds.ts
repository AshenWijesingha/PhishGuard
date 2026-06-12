/**
 * URL-list threat-feed adapters (N1): PhishTank, OpenPhish, URLhaus, and a
 * generic adapter for enterprise feeds (MISP exports / custom REST
 * endpoints that return a URL list).
 *
 * Privacy & footprint: feeds are downloaded periodically and matched
 * LOCALLY — no per-URL queries ever leave the device. Entries are stored
 * as truncated SHA-256 hashes (8 bytes, base64) of the canonical
 * "host/path?query" string, plus a separate set of host-only hashes for
 * whole-domain entries, keeping even large feeds to a few MB.
 *
 * All feeds are disabled by default (bandwidth + third-party fetch are
 * opt-in) and degrade gracefully offline: a failed refresh keeps the
 * previous cache.
 */
import type { TiAdapter, TiVerdict } from './adapter';
import { canonicalizeUrl } from './url-expressions';
import type { FeedConfig } from '../storage/settings';

const MAX_ENTRIES = 100_000;

async function entryHash(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return btoa(String.fromCharCode(...digest.slice(0, 8)));
}

interface FeedCache {
  updatedAt: number;
  /** Hashes of canonical host/path?query strings. */
  urlHashes: string[];
  /** Hashes of bare hosts, for entries that block a whole domain. */
  hostHashes: string[];
}

export interface FeedSpec {
  name: string;
  threatType: string;
  /** Builds the download URL (may embed an API key). */
  feedUrl(config: FeedConfig): string;
  /** Extra request headers (e.g. Authorization for enterprise feeds). */
  headers?(config: FeedConfig): Record<string, string>;
  /** Extracts raw URLs from the response body. */
  parse(body: string): string[];
}

/** Parses line-delimited URL lists (OpenPhish, URLhaus, MISP text export). */
export function parseUrlLines(body: string): string[] {
  return body
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#') && /^https?:\/\//i.test(l));
}

/** Parses PhishTank's online-valid.json (array of { url, ... }). */
export function parsePhishtankJson(body: string): string[] {
  try {
    const data = JSON.parse(body) as { url?: string }[];
    return data.map((e) => e.url ?? '').filter((u) => /^https?:\/\//i.test(u));
  } catch {
    return [];
  }
}

/** Parses either a JSON array (strings or {url}) or falls back to lines. */
export function parseGeneric(body: string): string[] {
  const trimmed = body.trim();
  if (trimmed.startsWith('[')) {
    try {
      const data = JSON.parse(trimmed) as (string | { url?: string })[];
      return data
        .map((e) => (typeof e === 'string' ? e : e.url ?? ''))
        .filter((u) => /^https?:\/\//i.test(u));
    } catch {
      return [];
    }
  }
  return parseUrlLines(body);
}

export const FEED_SPECS: Record<string, FeedSpec> = {
  phishtank: {
    name: 'phishtank',
    threatType: 'PHISHING',
    feedUrl: (c) =>
      c.url ||
      (c.apiKey
        ? `https://data.phishtank.com/data/${encodeURIComponent(c.apiKey)}/online-valid.json`
        : 'https://data.phishtank.com/data/online-valid.json'),
    parse: parsePhishtankJson,
  },
  openphish: {
    name: 'openphish',
    threatType: 'PHISHING',
    feedUrl: (c) => c.url || 'https://openphish.com/feed.txt',
    parse: parseUrlLines,
  },
  urlhaus: {
    name: 'urlhaus',
    threatType: 'MALWARE_DISTRIBUTION',
    feedUrl: (c) => c.url || 'https://urlhaus.abuse.ch/downloads/text_online/',
    parse: parseUrlLines,
  },
  custom: {
    name: 'custom',
    threatType: 'ENTERPRISE_BLOCKLIST',
    feedUrl: (c) => c.url,
    headers: (c): Record<string, string> => (c.apiKey ? { authorization: `Bearer ${c.apiKey}` } : {}),
    parse: parseGeneric,
  },
};

/** Canonical matching key for a feed entry or a URL under test. */
export async function urlKeys(rawUrl: string): Promise<{ urlKey: string; hostKey: string } | null> {
  const canon = canonicalizeUrl(rawUrl);
  if (!canon) return null;
  const slash = canon.indexOf('/');
  const host = slash === -1 ? canon : canon.slice(0, slash);
  // Treat trailing-slash and no-path forms identically.
  const normalized = canon.endsWith('/') ? canon.slice(0, -1) : canon;
  return { urlKey: await entryHash(normalized), hostKey: await entryHash(host) };
}

export class UrlFeedAdapter implements TiAdapter {
  readonly name: string;
  /** In-memory Set view of the cache, rebuilt when updatedAt changes. */
  private memo: { updatedAt: number; urls: Set<string>; hosts: Set<string> } | null = null;

  constructor(
    private spec: FeedSpec,
    private getConfig: () => Promise<FeedConfig>,
  ) {
    this.name = spec.name;
  }

  private get storageKey(): string {
    return `pg_feed_${this.spec.name}`;
  }

  async isEnabled(): Promise<boolean> {
    const c = await this.getConfig();
    return c.enabled && this.spec.feedUrl(c).length > 0;
  }

  async refresh(): Promise<void> {
    const config = await this.getConfig();
    if (!config.enabled) return;
    const url = this.spec.feedUrl(config);
    if (!url) return;
    try {
      const res = await fetch(url, { headers: this.spec.headers?.(config) ?? {} });
      if (!res.ok) return;
      const entries = this.spec.parse(await res.text()).slice(0, MAX_ENTRIES);
      const urlHashes = new Set<string>();
      const hostHashes = new Set<string>();
      for (const entry of entries) {
        const keys = await urlKeys(entry);
        if (!keys) continue;
        const canon = canonicalizeUrl(entry)!;
        const path = canon.slice(canon.indexOf('/'));
        // A bare-domain entry ("/" or no path) blocks the whole host.
        if (path === '/' || path === '') hostHashes.add(keys.hostKey);
        else urlHashes.add(keys.urlKey);
      }
      const cache: FeedCache = {
        updatedAt: Date.now(),
        urlHashes: [...urlHashes],
        hostHashes: [...hostHashes],
      };
      await chrome.storage.local.set({ [this.storageKey]: cache });
    } catch {
      // Offline / feed error: keep the previous cache.
    }
  }

  async checkUrl(url: string): Promise<TiVerdict | null> {
    if (!(await this.isEnabled())) return null;
    const cache = ((await chrome.storage.local.get(this.storageKey))[this.storageKey] as FeedCache | undefined) ?? null;
    if (!cache || (cache.urlHashes.length === 0 && cache.hostHashes.length === 0)) return null;
    if (!this.memo || this.memo.updatedAt !== cache.updatedAt) {
      this.memo = { updatedAt: cache.updatedAt, urls: new Set(cache.urlHashes), hosts: new Set(cache.hostHashes) };
    }
    const keys = await urlKeys(url);
    if (!keys) return null;
    if (this.memo.hosts.has(keys.hostKey) || this.memo.urls.has(keys.urlKey)) {
      return { source: this.name, threatType: this.spec.threatType };
    }
    return null;
  }
}
