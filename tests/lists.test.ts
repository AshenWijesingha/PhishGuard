/**
 * Allow/blocklist management: normalization, matching, and the mutual-
 * exclusivity guarantee (a domain can never be on both lists at once).
 */
import { beforeEach, describe, expect, it } from 'vitest';
import {
  addToAllowlist, addToBlocklist, getAllowlist, getBlocklist,
  isAllowlisted, isBlocklisted, normalizeDomain, removeFromAllowlist,
} from '../src/storage/lists';

beforeEach(() => {
  const store: Record<string, unknown> = {};
  (globalThis as never as { chrome: unknown }).chrome = {
    storage: {
      local: {
        get: async (key: string) => ({ [key]: store[key] }),
        set: async (obj: Record<string, unknown>) => Object.assign(store, obj),
      },
    },
  };
});

describe('normalizeDomain', () => {
  it('extracts the hostname from URLs and trims dots/case', () => {
    expect(normalizeDomain('https://Evil.Example/path?q=1')).toBe('evil.example');
    expect(normalizeDomain('  EXAMPLE.com. ')).toBe('example.com');
    expect(normalizeDomain('plain.example')).toBe('plain.example');
  });
});

describe('list membership', () => {
  it('matches subdomains of a listed domain', async () => {
    await addToAllowlist('trusted.example');
    expect(await isAllowlisted('https://login.trusted.example/page')).toBe(true);
    expect(await isAllowlisted('https://nottrusted.example/')).toBe(false);
  });

  it('removal works', async () => {
    await addToAllowlist('a.example');
    await removeFromAllowlist('a.example');
    expect(await getAllowlist()).toEqual([]);
  });
});

describe('mutual exclusivity (a domain is never on both lists)', () => {
  it('adding to the allowlist removes the domain from the blocklist', async () => {
    await addToBlocklist('flip.example');
    expect(await getBlocklist()).toContain('flip.example');

    const res = await addToAllowlist('flip.example');
    expect(res.movedFromOtherList).toBe(true);
    expect(await getAllowlist()).toContain('flip.example');
    expect(await getBlocklist()).not.toContain('flip.example');
    expect(await isBlocklisted('https://flip.example/')).toBe(false);
    expect(await isAllowlisted('https://flip.example/')).toBe(true);
  });

  it('adding to the blocklist removes the domain from the allowlist', async () => {
    await addToAllowlist('flop.example');
    const res = await addToBlocklist('flop.example');
    expect(res.movedFromOtherList).toBe(true);
    expect(await getBlocklist()).toContain('flop.example');
    expect(await getAllowlist()).not.toContain('flop.example');
  });

  it('reports no move when the domain was not on the other list', async () => {
    const res = await addToAllowlist('fresh.example');
    expect(res.movedFromOtherList).toBe(false);
  });

  it('normalizes before comparing across lists', async () => {
    await addToBlocklist('https://Mixed.Example/login');
    const res = await addToAllowlist('mixed.example');
    expect(res.movedFromOtherList).toBe(true);
    expect(await getBlocklist()).toEqual([]);
  });

  it('deduplicates repeated adds', async () => {
    await addToAllowlist('dup.example');
    await addToAllowlist('dup.example');
    expect(await getAllowlist()).toEqual(['dup.example']);
  });
});
