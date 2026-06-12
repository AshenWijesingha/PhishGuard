/**
 * Google Safe Browsing (Update API v4) adapter with a local hash-prefix
 * cache (M5). Privacy-preserving by design: full URLs are never sent —
 * matching happens against locally cached 4-byte SHA-256 prefixes, and
 * only on a local prefix hit is a fullHashes lookup made (sending hash
 * prefixes only, per the k-anonymity scheme).
 *
 * Degrades gracefully: no API key, no network, or API errors all resolve
 * to "no hit" and the rest of the engine keeps working on heuristics.
 */
import type { TiAdapter, TiVerdict } from './adapter';
import { urlExpressions } from './url-expressions';

const API = 'https://safebrowsing.googleapis.com/v4';
const CLIENT = { clientId: 'phishguard', clientVersion: '1.0.0' };
const THREAT_TYPES = ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE'];

const PREFIX_KEY = 'pg_gsb_prefixes'; // { [threatType]: { state: string, prefixes: string[] (base64 4-byte) } }
const FULLHASH_CACHE_KEY = 'pg_gsb_fullhash_cache'; // { [fullHashB64]: { threatType, expires } }

interface PrefixStore {
  [threatType: string]: { state: string; prefixes: string[] };
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource));
}

function b64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function b64decode(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export class SafeBrowsingAdapter implements TiAdapter {
  readonly name = 'google-safe-browsing';

  constructor(private getApiKey: () => Promise<string>) {}

  async isEnabled(): Promise<boolean> {
    return (await this.getApiKey()).length > 0;
  }

  /** Downloads incremental hash-prefix list updates into storage.local. */
  async refresh(): Promise<void> {
    const key = await this.getApiKey();
    if (!key) return;
    const store = ((await chrome.storage.local.get(PREFIX_KEY))[PREFIX_KEY] as PrefixStore | undefined) ?? {};
    try {
      const res = await fetch(`${API}/threatListUpdates:fetch?key=${encodeURIComponent(key)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client: CLIENT,
          listUpdateRequests: THREAT_TYPES.map((t) => ({
            threatType: t,
            platformType: 'ANY_PLATFORM',
            threatEntryType: 'URL',
            state: store[t]?.state ?? '',
            constraints: { supportedCompressions: ['RAW'], maxDatabaseEntries: 262144 },
          })),
        }),
      });
      if (!res.ok) return;
      const body = (await res.json()) as {
        listUpdateResponses?: {
          threatType: string;
          responseType: string;
          newClientState: string;
          additions?: { rawHashes?: { prefixSize: number; rawHashes: string } }[];
          removals?: { rawIndices?: { indices: number[] } }[];
        }[];
      };
      for (const upd of body.listUpdateResponses ?? []) {
        let prefixes = upd.responseType === 'FULL_UPDATE' ? [] : (store[upd.threatType]?.prefixes ?? []);
        // Removals are indices into the lexicographically sorted list.
        const removeIdx = new Set(upd.removals?.flatMap((r) => r.rawIndices?.indices ?? []) ?? []);
        if (removeIdx.size > 0) {
          prefixes = prefixes.filter((_, i) => !removeIdx.has(i));
        }
        for (const add of upd.additions ?? []) {
          const raw = add.rawHashes;
          if (!raw) continue;
          const bytes = b64decode(raw.rawHashes);
          for (let off = 0; off + raw.prefixSize <= bytes.length; off += raw.prefixSize) {
            prefixes.push(b64(bytes.slice(off, off + raw.prefixSize)));
          }
        }
        prefixes.sort();
        store[upd.threatType] = { state: upd.newClientState, prefixes };
      }
      await chrome.storage.local.set({ [PREFIX_KEY]: store });
    } catch {
      // Offline / API error: keep the existing cache.
    }
  }

  async checkUrl(url: string): Promise<TiVerdict | null> {
    const store = ((await chrome.storage.local.get(PREFIX_KEY))[PREFIX_KEY] as PrefixStore | undefined) ?? {};
    const haveAnyPrefixes = Object.values(store).some((s) => s.prefixes.length > 0);
    if (!haveAnyPrefixes) return null;

    // Hash every URL expression; collect 4-byte prefixes that match locally.
    const expressions = urlExpressions(url);
    const fullHashes = new Map<string, Uint8Array>(); // prefixB64 -> full hash
    for (const expr of expressions) {
      const hash = await sha256(new TextEncoder().encode(expr));
      fullHashes.set(b64(hash.slice(0, 4)), hash);
    }

    const localHits: { threatType: string; prefixB64: string }[] = [];
    for (const [threatType, { prefixes }] of Object.entries(store)) {
      const set = new Set(prefixes);
      for (const prefixB64 of fullHashes.keys()) {
        if (set.has(prefixB64)) localHits.push({ threatType, prefixB64 });
      }
    }
    if (localHits.length === 0) return null;

    // Check the positive full-hash cache before going to the network.
    const fhCache =
      ((await chrome.storage.local.get(FULLHASH_CACHE_KEY))[FULLHASH_CACHE_KEY] as
        | Record<string, { threatType: string; expires: number }>
        | undefined) ?? {};
    for (const { prefixB64 } of localHits) {
      const full = b64(fullHashes.get(prefixB64)!);
      const cached = fhCache[full];
      if (cached && cached.expires > Date.now()) {
        return { source: this.name, threatType: cached.threatType };
      }
    }

    return this.findFullHashes(localHits, fullHashes, fhCache);
  }

  private async findFullHashes(
    localHits: { threatType: string; prefixB64: string }[],
    fullHashes: Map<string, Uint8Array>,
    fhCache: Record<string, { threatType: string; expires: number }>,
  ): Promise<TiVerdict | null> {
    const key = await this.getApiKey();
    if (!key) return null;
    try {
      const res = await fetch(`${API}/fullHashes:find?key=${encodeURIComponent(key)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client: CLIENT,
          clientStates: [],
          threatInfo: {
            threatTypes: THREAT_TYPES,
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [...new Set(localHits.map((h) => h.prefixB64))].map((hash) => ({ hash })),
          },
        }),
      });
      if (!res.ok) return null;
      const body = (await res.json()) as {
        matches?: { threatType: string; threat: { hash: string }; cacheDuration?: string }[];
      };
      let verdict: TiVerdict | null = null;
      for (const m of body.matches ?? []) {
        const ttlSec = parseFloat(m.cacheDuration ?? '300s') || 300;
        fhCache[m.threat.hash] = { threatType: m.threatType, expires: Date.now() + ttlSec * 1000 };
        for (const full of fullHashes.values()) {
          if (b64(full) === m.threat.hash) {
            verdict = { source: this.name, threatType: m.threatType };
          }
        }
      }
      await chrome.storage.local.set({ [FULLHASH_CACHE_KEY]: fhCache });
      return verdict;
    } catch {
      return null; // offline-tolerant
    }
  }
}
