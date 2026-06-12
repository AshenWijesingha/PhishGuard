/**
 * Google Safe Browsing URL canonicalization and host/path suffix-prefix
 * expression generation (Update API v4 spec). Pure functions, unit-tested.
 */

export function canonicalizeUrl(rawUrl: string): string | null {
  let url: URL;
  try {
    url = new URL(rawUrl.trim());
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;

  // Repeatedly percent-unescape.
  const unescapeAll = (s: string): string => {
    let prev = s;
    for (let i = 0; i < 20; i++) {
      let next: string;
      try {
        next = decodeURIComponent(prev.replace(/\+/g, '%2B'));
      } catch {
        break;
      }
      if (next === prev) break;
      prev = next;
    }
    return prev;
  };

  let host = unescapeAll(url.hostname).toLowerCase().replace(/^\.+|\.+$/g, '').replace(/\.{2,}/g, '.');
  // Decimal/hex IP normalization
  if (/^(0x[0-9a-f]+|\d+)$/i.test(host)) {
    const n = host.startsWith('0x') ? parseInt(host, 16) : parseInt(host, 10);
    if (Number.isFinite(n) && n >= 0 && n <= 0xffffffff) {
      host = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
    }
  }

  let path = unescapeAll(url.pathname);
  // Resolve /./ and /../ sequences
  const parts: string[] = [];
  for (const seg of path.split('/')) {
    if (seg === '.' || seg === '') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  path = '/' + parts.join('/') + (path.endsWith('/') && parts.length > 0 ? '/' : '');
  if (path === '//') path = '/';

  const escapeMin = (s: string): string =>
    [...s].map((c) => {
      const code = c.charCodeAt(0);
      return code <= 32 || code >= 127 || c === '#' || c === '%' ? `%${code.toString(16).toUpperCase().padStart(2, '0')}` : c;
    }).join('');

  const query = url.search; // keep as-is per spec (minus fragment)
  return `${escapeMin(host)}${escapeMin(path)}${query}`;
}

/**
 * Generates the host-suffix / path-prefix expressions for a URL per the
 * Safe Browsing spec (max 5 host suffixes × up to 6 path prefixes).
 */
export function urlExpressions(rawUrl: string): string[] {
  const canon = canonicalizeUrl(rawUrl);
  if (!canon) return [];
  const slash = canon.indexOf('/');
  const host = slash === -1 ? canon : canon.slice(0, slash);
  const pathAndQuery = slash === -1 ? '/' : canon.slice(slash);
  const qIdx = pathAndQuery.indexOf('?');
  const path = qIdx === -1 ? pathAndQuery : pathAndQuery.slice(0, qIdx);

  const hosts: string[] = [host];
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const labels = host.split('.');
    for (let i = 1; i <= Math.min(4, labels.length - 2); i++) {
      hosts.push(labels.slice(i).join('.'));
    }
  }

  const paths: string[] = [];
  if (qIdx !== -1) paths.push(pathAndQuery); // exact path + query
  paths.push(path);
  const segs = path.split('/').filter(Boolean);
  let acc = '';
  for (let i = 0; i < Math.min(3, segs.length - (path.endsWith('/') ? 0 : 1)); i++) {
    acc += `/${segs[i]}`;
    paths.push(`${acc}/`);
  }
  if (!paths.includes('/')) paths.push('/');

  const out = new Set<string>();
  for (const h of hosts) for (const p of paths) out.add(h + p);
  return [...out];
}
