/**
 * TI adapter tests: Safe Browsing URL canonicalization/expressions and the
 * local hash-prefix cache behaviour (offline tolerance, full-hash caching).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { canonicalizeUrl, urlExpressions } from '../src/intel/url-expressions';
import { SafeBrowsingAdapter } from '../src/intel/safebrowsing';

describe('GSB URL canonicalization', () => {
  it('lowercases host and strips fragments', () => {
    expect(canonicalizeUrl('HTTP://Host.COM/path#frag')).toBe('host.com/path');
  });
  it('resolves dot segments', () => {
    expect(canonicalizeUrl('http://host.com/a/b/../c/./d')).toBe('host.com/a/c/d');
  });
  it('normalizes decimal IP hosts', () => {
    expect(canonicalizeUrl('http://3279880203/blah')).toBe('195.127.0.11/blah');
  });
  it('rejects non-http(s) schemes', () => {
    expect(canonicalizeUrl('ftp://host.com/')).toBeNull();
  });
});

describe('GSB URL expressions', () => {
  it('generates host-suffix/path-prefix combinations', () => {
    const exprs = urlExpressions('http://a.b.c.d.example.com/1/2.html?param=1');
    expect(exprs).toContain('a.b.c.d.example.com/1/2.html?param=1');
    expect(exprs).toContain('example.com/');
    expect(exprs).toContain('d.example.com/1/');
    // host suffixes capped at 5 (full host + 4)
    const hosts = new Set(exprs.map((e) => e.split('/')[0]));
    expect(hosts.size).toBeLessThanOrEqual(5);
  });
});

// ---------------------------------------------------------------------------
// chrome.storage.local mock

function mockChromeStorage(): Record<string, unknown> {
  const store: Record<string, unknown> = {};
  (globalThis as never as { chrome: unknown }).chrome = {
    storage: {
      local: {
        get: async (key: string) => ({ [key]: store[key] }),
        set: async (obj: Record<string, unknown>) => Object.assign(store, obj),
      },
    },
  };
  return store;
}

async function prefixOf(expression: string): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(expression)));
  return btoa(String.fromCharCode(...hash.slice(0, 4)));
}

describe('SafeBrowsingAdapter caching (M5)', () => {
  let store: Record<string, unknown>;
  beforeEach(() => {
    store = mockChromeStorage();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('is disabled without an API key and returns no hit', async () => {
    const adapter = new SafeBrowsingAdapter(async () => '');
    expect(await adapter.isEnabled()).toBe(false);
    expect(await adapter.checkUrl('https://evil.example/')).toBeNull();
  });

  it('returns null with no local prefix match and makes no network call', async () => {
    store['pg_gsb_prefixes'] = { SOCIAL_ENGINEERING: { state: 's', prefixes: [await prefixOf('other.example/')] } };
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const adapter = new SafeBrowsingAdapter(async () => 'key');
    expect(await adapter.checkUrl('https://clean.example/page')).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('confirms a local prefix hit via fullHashes and caches the result', async () => {
    const expression = 'evil.example/';
    store['pg_gsb_prefixes'] = { SOCIAL_ENGINEERING: { state: 's', prefixes: [await prefixOf(expression)] } };
    const fullHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(expression)));
    const fullB64 = btoa(String.fromCharCode(...fullHash));
    const fetchSpy = vi.fn(async () =>
      new Response(JSON.stringify({
        matches: [{ threatType: 'SOCIAL_ENGINEERING', threat: { hash: fullB64 }, cacheDuration: '300s' }],
      })),
    );
    vi.stubGlobal('fetch', fetchSpy);

    const adapter = new SafeBrowsingAdapter(async () => 'key');
    const v1 = await adapter.checkUrl('https://evil.example/');
    expect(v1?.threatType).toBe('SOCIAL_ENGINEERING');
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // Second lookup is served from the positive full-hash cache.
    const v2 = await adapter.checkUrl('https://evil.example/');
    expect(v2?.threatType).toBe('SOCIAL_ENGINEERING');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('degrades gracefully when the network is down (offline tolerance)', async () => {
    const expression = 'evil.example/';
    store['pg_gsb_prefixes'] = { SOCIAL_ENGINEERING: { state: 's', prefixes: [await prefixOf(expression)] } };
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new TypeError('network down');
    }));
    const adapter = new SafeBrowsingAdapter(async () => 'key');
    await expect(adapter.checkUrl('https://evil.example/')).resolves.toBeNull();
    await expect(adapter.refresh()).resolves.toBeUndefined();
  });
});
