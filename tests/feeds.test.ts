/**
 * URL-list feed adapters (N1): parsing, local hashed matching, offline
 * tolerance, and enable/disable behaviour.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { FEED_SPECS, UrlFeedAdapter, parseGeneric, parsePhishtankJson, parseUrlLines } from '../src/intel/feeds';
import type { FeedConfig } from '../src/storage/settings';

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

const config = (over: Partial<FeedConfig> = {}): FeedConfig => ({ enabled: true, apiKey: '', url: '', ...over });

describe('feed parsers', () => {
  it('parses line-delimited URL lists, skipping comments', () => {
    expect(parseUrlLines('# header\nhttps://a.example/x\n\nhttp://b.example/\nnot-a-url\n')).toEqual([
      'https://a.example/x',
      'http://b.example/',
    ]);
  });
  it('parses PhishTank JSON', () => {
    const body = JSON.stringify([{ url: 'https://phish.example/login', phish_id: 1 }, { url: 'bad' }]);
    expect(parsePhishtankJson(body)).toEqual(['https://phish.example/login']);
    expect(parsePhishtankJson('not json')).toEqual([]);
  });
  it('parses generic JSON arrays of strings or {url} objects', () => {
    expect(parseGeneric('["https://x.example/a"]')).toEqual(['https://x.example/a']);
    expect(parseGeneric('[{"url":"https://y.example/b"}]')).toEqual(['https://y.example/b']);
    expect(parseGeneric('https://z.example/c\n')).toEqual(['https://z.example/c']);
  });
});

describe('UrlFeedAdapter (N1)', () => {
  beforeEach(() => {
    mockChromeStorage();
    vi.restoreAllMocks();
  });

  it('is disabled by default config', async () => {
    const adapter = new UrlFeedAdapter(FEED_SPECS.openphish!, async () => config({ enabled: false }));
    expect(await adapter.isEnabled()).toBe(false);
    expect(await adapter.checkUrl('https://phish.example/login')).toBeNull();
  });

  it('matches exact URLs and whole-domain entries after refresh', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response('https://phish.example/steal/credentials.php\nhttps://evil-domain.example/\n'),
    ));
    const adapter = new UrlFeedAdapter(FEED_SPECS.openphish!, async () => config());
    await adapter.refresh();

    // Exact URL entry: matches that path, not others on the same host.
    expect(await adapter.checkUrl('https://phish.example/steal/credentials.php')).toMatchObject({
      source: 'openphish',
    });
    expect(await adapter.checkUrl('https://phish.example/other')).toBeNull();

    // Whole-domain entry: matches any path on the host.
    expect(await adapter.checkUrl('https://evil-domain.example/any/path?q=1')).toMatchObject({
      threatType: 'PHISHING',
    });
  });

  it('keeps the previous cache when a refresh fails (offline tolerance)', async () => {
    const fetchMock = vi.fn(async () => new Response('https://phish.example/login\n'));
    vi.stubGlobal('fetch', fetchMock);
    const adapter = new UrlFeedAdapter(FEED_SPECS.openphish!, async () => config());
    await adapter.refresh();
    expect(await adapter.checkUrl('https://phish.example/login')).not.toBeNull();

    fetchMock.mockImplementation(async () => {
      throw new TypeError('offline');
    });
    await adapter.refresh(); // must not throw
    expect(await adapter.checkUrl('https://phish.example/login')).not.toBeNull();
  });

  it('sends a Bearer token for the enterprise adapter', async () => {
    const fetchMock = vi.fn(async () => new Response('https://blocked.corp/x\n'));
    vi.stubGlobal('fetch', fetchMock);
    const adapter = new UrlFeedAdapter(
      FEED_SPECS.custom!,
      async () => config({ url: 'https://soc.corp/feed.txt', apiKey: 'sekret' }),
    );
    await adapter.refresh();
    expect(fetchMock).toHaveBeenCalledWith('https://soc.corp/feed.txt', {
      headers: { authorization: 'Bearer sekret' },
    });
  });
});
