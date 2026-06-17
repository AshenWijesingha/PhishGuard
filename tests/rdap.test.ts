/**
 * RDAP domain-age lookups (N2): caching, negative caching, and offline
 * tolerance.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getDomainAgeDays } from '../src/intel/rdap';

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

const rdapResponse = (registeredIso: string) =>
  new Response(JSON.stringify({ events: [{ eventAction: 'registration', eventDate: registeredIso }] }));

describe('getDomainAgeDays (N2)', () => {
  beforeEach(() => {
    mockChromeStorage();
    vi.restoreAllMocks();
  });

  it('computes age from the registration event', async () => {
    const now = Date.parse('2026-06-12T00:00:00Z');
    vi.stubGlobal('fetch', vi.fn(async () => rdapResponse('2026-06-05T00:00:00Z')));
    expect(await getDomainAgeDays('fresh-phish.example', now)).toBe(7);
  });

  it('caches lookups (one fetch for repeated queries)', async () => {
    const now = Date.now();
    const fetchMock = vi.fn(async () => rdapResponse(new Date(now - 100 * 86400_000).toISOString()));
    vi.stubGlobal('fetch', fetchMock);
    await getDomainAgeDays('cached.example', now);
    await getDomainAgeDays('cached.example', now);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('returns null and negative-caches failures', async () => {
    const now = Date.now();
    const fetchMock = vi.fn(async () => {
      throw new TypeError('offline');
    });
    vi.stubGlobal('fetch', fetchMock);
    expect(await getDomainAgeDays('unreachable.example', now)).toBeNull();
    expect(await getDomainAgeDays('unreachable.example', now)).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1); // negative cache hit
  });

  it('rejects invalid input', async () => {
    expect(await getDomainAgeDays('')).toBeNull();
    expect(await getDomainAgeDays('localhost')).toBeNull();
  });
});
