/**
 * Password-reuse guard (N10): reuse detection across origins, salted
 * storage (no plaintext or unsalted digests at rest).
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { isPasswordReused, recordPasswordUse } from '../src/storage/password-reuse';

let store: Record<string, unknown>;

beforeEach(() => {
  store = {};
  (globalThis as never as { chrome: unknown }).chrome = {
    storage: {
      local: {
        get: async (key: string) => ({ [key]: store[key] }),
        set: async (obj: Record<string, unknown>) => Object.assign(store, obj),
      },
    },
  };
});

const digest = 'a'.repeat(64); // stand-in SHA-256 hex from the content script

describe('password-reuse guard (N10)', () => {
  it('does not flag a never-seen password', async () => {
    expect(await isPasswordReused(digest, 'https://site-a.example')).toBe(false);
  });

  it('does not flag reuse on the same origin', async () => {
    await recordPasswordUse(digest, 'https://site-a.example');
    expect(await isPasswordReused(digest, 'https://site-a.example')).toBe(false);
  });

  it('flags reuse on a different origin', async () => {
    await recordPasswordUse(digest, 'https://site-a.example');
    expect(await isPasswordReused(digest, 'https://site-b.example')).toBe(true);
  });

  it('distinguishes different passwords', async () => {
    await recordPasswordUse(digest, 'https://site-a.example');
    expect(await isPasswordReused('b'.repeat(64), 'https://site-b.example')).toBe(false);
  });

  it('stores neither the digest nor the origin in recognizable form', async () => {
    await recordPasswordUse(digest, 'https://site-a.example');
    const raw = JSON.stringify(store);
    expect(raw).not.toContain(digest);
    expect(raw).not.toContain('site-a.example');
  });
});
