/**
 * Local allowlist ("this is a false positive") and blocklist management
 * (M11). Stored in chrome.storage.local; matching is by registrable domain
 * with subdomain inheritance.
 */
import { parseHost } from '../core/url-heuristics';

const ALLOW_KEY = 'pg_allowlist';
const BLOCK_KEY = 'pg_blocklist';

async function getList(key: string): Promise<string[]> {
  return ((await chrome.storage.local.get(key))[key] as string[] | undefined) ?? [];
}

async function setList(key: string, list: string[]): Promise<void> {
  await chrome.storage.local.set({ [key]: [...new Set(list)].sort() });
}

export function normalizeDomain(input: string): string {
  let d = input.trim().toLowerCase();
  try {
    if (d.includes('/') || d.includes(':')) d = new URL(d.includes('://') ? d : `https://${d}`).hostname;
  } catch {
    /* keep as typed */
  }
  return d.replace(/^\.+|\.+$/g, '');
}

function domainMatches(hostname: string, listed: string): boolean {
  return hostname === listed || hostname.endsWith(`.${listed}`);
}

export async function getAllowlist(): Promise<string[]> {
  return getList(ALLOW_KEY);
}

export async function getBlocklist(): Promise<string[]> {
  return getList(BLOCK_KEY);
}

export async function addToAllowlist(domain: string): Promise<void> {
  const d = normalizeDomain(domain);
  if (!d) return;
  await setList(ALLOW_KEY, [...(await getAllowlist()), d]);
}

export async function removeFromAllowlist(domain: string): Promise<void> {
  const d = normalizeDomain(domain);
  await setList(ALLOW_KEY, (await getAllowlist()).filter((x) => x !== d));
}

export async function addToBlocklist(domain: string): Promise<void> {
  const d = normalizeDomain(domain);
  if (!d) return;
  await setList(BLOCK_KEY, [...(await getBlocklist()), d]);
}

export async function removeFromBlocklist(domain: string): Promise<void> {
  await setList(BLOCK_KEY, (await getBlocklist()).filter((x) => x !== normalizeDomain(domain)));
}

export async function isAllowlisted(url: string): Promise<boolean> {
  return matchesList(url, await getAllowlist());
}

export async function isBlocklisted(url: string): Promise<boolean> {
  return matchesList(url, await getBlocklist());
}

function matchesList(url: string, list: string[]): boolean {
  let hostname: string;
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    hostname = normalizeDomain(url);
  }
  const reg = parseHost(hostname).registrableDomain || hostname;
  return list.some((d) => domainMatches(hostname, d) || domainMatches(reg, d));
}
