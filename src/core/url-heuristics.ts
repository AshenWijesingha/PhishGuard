/**
 * URL heuristics (M1): homoglyph/punycode detection, typosquat distance
 * against the bundled brand list, suspicious subdomain nesting, IP-literal
 * hosts, userinfo tricks, suspicious TLDs, and URL-shortener flagging.
 *
 * Pure functions — no chrome.* APIs — so everything here is unit-testable
 * and reusable from both the service worker and content scripts.
 */
import { BRANDS, BRAND_DOMAIN_SET, BRAND_SLD_SET } from './brands';
import { hasConfusables, isMixedScript, toSkeleton } from './confusables';
import type { Signal } from './scoring';

// ---------------------------------------------------------------------------
// Parsing helpers

/** Multi-part public suffixes we recognize (practical subset of the PSL). */
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'co.kr', 'or.kr', 'go.kr',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.ve',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'com.hk', 'com.sg', 'com.my', 'com.ph', 'com.tw', 'com.vn',
  'co.za', 'org.za', 'co.il', 'org.il', 'com.tr',
  'com.pl', 'com.ru', 'com.ua', 'com.eg', 'com.sa', 'com.ng',
]);

const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'club',
  'work', 'support', 'click', 'link', 'gdn', 'loan', 'win', 'bid',
  'stream', 'racing', 'review', 'date', 'faith', 'science', 'party',
  'icu', 'rest', 'fit', 'cam', 'monster', 'quest', 'cyou', 'sbs',
  'cfd', 'bond', 'beauty', 'hair', 'skin', 'makeup', 'autos', 'boats',
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'lnkd.in',
  'bl.ink', 's.id', 'v.gd', 'qr.ae', 'tiny.cc', 'shor.tt', 'soo.gd',
  'short.io', 'bitly.com', 'href.li', 'tr.im', 'u.to', 'x.gd',
]);

export interface ParsedHost {
  /** Hostname exactly as the URL API yields it (lowercase, punycode). */
  hostname: string;
  /** Hostname with any xn-- labels decoded to Unicode. */
  unicodeHostname: string;
  /** e.g. "paypal.com" or "example.co.uk". Empty for IP literals. */
  registrableDomain: string;
  /** Labels left of the registrable domain. */
  subdomainLabels: string[];
  tld: string;
  isIp: boolean;
}

export function isIpLiteral(hostname: string): boolean {
  if (/^\[?[0-9a-f:]+\]?$/i.test(hostname) && hostname.includes(':')) return true; // IPv6
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return true; // dotted IPv4
  if (/^0x[0-9a-f]+$/i.test(hostname) || /^\d{8,10}$/.test(hostname)) return true; // hex/decimal IPv4
  return false;
}

export function parseHost(hostname: string): ParsedHost {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (isIpLiteral(host)) {
    return { hostname: host, unicodeHostname: host, registrableDomain: '', subdomainLabels: [], tld: '', isIp: true };
  }
  const labels = host.split('.');
  let suffixLen = 1;
  if (labels.length >= 3) {
    const lastTwo = labels.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.has(lastTwo)) suffixLen = 2;
  }
  const regLabels = labels.slice(-(suffixLen + 1));
  const registrableDomain = labels.length > suffixLen ? regLabels.join('.') : host;
  const subdomainLabels = labels.slice(0, Math.max(0, labels.length - suffixLen - 1));
  const unicodeHostname = labels.map(decodeLabel).join('.');
  return {
    hostname: host,
    unicodeHostname,
    registrableDomain,
    subdomainLabels,
    tld: labels[labels.length - 1] ?? '',
    isIp: false,
  };
}

// ---------------------------------------------------------------------------
// Punycode (RFC 3492) decoding — enough to turn xn-- labels back into Unicode
// so the confusable detector can inspect them.

function punycodeDecode(input: string): string {
  const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;
  const output: number[] = [];
  let n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
  const lastDelim = input.lastIndexOf('-');
  for (let j = 0; j < Math.max(0, lastDelim); j++) {
    const cp = input.charCodeAt(j);
    if (cp >= 0x80) throw new Error('invalid punycode');
    output.push(cp);
  }
  let idx = lastDelim > 0 ? lastDelim + 1 : 0;
  while (idx < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new Error('invalid punycode');
      const c = input.charCodeAt(idx++);
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : BASE;
      if (digit >= BASE) throw new Error('invalid punycode');
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const numPoints = output.length + 1;
    let delta = i - oldi;
    delta = oldi === 0 ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k2 = 0;
    while (delta > ((BASE - TMIN) * TMAX) >> 1) {
      delta = Math.floor(delta / (BASE - TMIN));
      k2 += BASE;
    }
    bias = Math.floor(k2 + ((BASE - TMIN + 1) * delta) / (delta + SKEW));
    n += Math.floor(i / numPoints);
    i %= numPoints;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

export function decodeLabel(label: string): string {
  if (!label.startsWith('xn--')) return label;
  try {
    return punycodeDecode(label.slice(4));
  } catch {
    return label;
  }
}

// ---------------------------------------------------------------------------
// Edit distance

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = new Array<number>(n + 1);
  let curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n]!;
}

// ---------------------------------------------------------------------------
// Signal extraction

export interface UrlAnalysis {
  url: string;
  host: ParsedHost;
  signals: Signal[];
  /** Brand whose domain this host most plausibly impersonates, if any. */
  impersonatedBrand?: string;
}

export function analyzeUrl(rawUrl: string): UrlAnalysis {
  const signals: Signal[] = [];
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { url: rawUrl, host: parseHost(''), signals };
  }
  const host = parseHost(url.hostname);
  let impersonatedBrand: string | undefined;

  if (url.protocol === 'http:') {
    signals.push({ id: 'insecure_http', reason: 'The connection is not encrypted (HTTP, not HTTPS).' });
  }

  if (url.username || url.password) {
    signals.push({
      id: 'userinfo_in_url',
      reason: `The address hides its real destination: text before the “@” (“${url.username.slice(0, 40)}”) looks like a site name, but the browser actually goes to ${host.hostname}.`,
      detail: host.hostname,
    });
  }

  if (host.isIp) {
    signals.push({
      id: 'ip_literal_host',
      reason: `The site is addressed by a raw IP address (${host.hostname}) instead of a domain name — legitimate services almost never do this.`,
      detail: host.hostname,
    });
    return { url: rawUrl, host, signals };
  }

  // Punycode / homoglyph
  const hasPunycodeLabel = host.hostname.split('.').some((l) => l.startsWith('xn--'));
  if (hasPunycodeLabel) {
    signals.push({
      id: 'punycode',
      reason: `The domain uses internationalized characters (shown as “${host.unicodeHostname}”), a technique often used to imitate well-known names.`,
      detail: host.unicodeHostname,
    });
  }
  const uniReg = host.unicodeHostname.split('.').slice(-2).join('.');
  if (hasConfusables(uniReg) || (hasPunycodeLabel && isMixedScript(host.unicodeHostname))) {
    const skeleton = toSkeleton(host.unicodeHostname);
    const skelReg = parseHost(skeleton).registrableDomain;
    const matchedBrand = BRAND_DOMAIN_SET.has(skelReg)
      ? skelReg
      : [...BRAND_DOMAIN_SET].find((d) => levenshtein(skelReg, d) <= 1);
    if (matchedBrand) {
      impersonatedBrand = matchedBrand;
      signals.push({
        id: 'homoglyph',
        reason: `The domain “${host.unicodeHostname}” uses lookalike characters to imitate ${matchedBrand}. It is NOT ${matchedBrand}.`,
        detail: matchedBrand,
      });
    } else if (isMixedScript(host.unicodeHostname)) {
      signals.push({
        id: 'homoglyph',
        reason: `The domain “${host.unicodeHostname}” mixes alphabets in a way commonly used to disguise fake addresses.`,
      });
    }
  }

  // Typosquat distance against brand domains (skip exact legitimate matches)
  if (!BRAND_DOMAIN_SET.has(host.registrableDomain)) {
    const sld = host.registrableDomain.split('.')[0] ?? '';
    const sldSkeleton = toSkeleton(decodeLabel(sld));
    for (const brand of BRANDS) {
      for (const legit of brand.domains) {
        const legitSld = legit.split('.')[0]!;
        if (legitSld.length < 4) continue; // too short for meaningful distance
        const dist = levenshtein(sldSkeleton, legitSld);
        const threshold = legitSld.length >= 8 ? 2 : 1;
        if (dist > 0 && dist <= threshold && !BRAND_SLD_SET.has(sldSkeleton)) {
          impersonatedBrand ??= legit;
          signals.push({
            id: 'typosquat',
            reason: `The domain “${host.registrableDomain}” is one keystroke away from “${legit}” — a classic lookalike trick. It is NOT ${brand.name}.`,
            detail: legit,
          });
          break;
        }
      }
      if (impersonatedBrand) break;
    }

    // Brand name buried in subdomain: paypal.com.secure-login.example.tld
    const subSkeleton = toSkeleton(host.subdomainLabels.join('.'));
    for (const brand of BRANDS) {
      const brandSld = brand.domains[0]!.split('.')[0]!;
      if (brandSld.length < 4) continue;
      if (subSkeleton.split(/[.-]/).includes(brandSld)) {
        impersonatedBrand ??= brand.domains[0];
        signals.push({
          id: 'brand_in_subdomain',
          reason: `“${brandSld}” appears in the address, but the actual site is “${host.registrableDomain}”, which is unrelated to ${brand.name}.`,
          detail: host.registrableDomain,
        });
        break;
      }
    }
  }

  if (host.subdomainLabels.length >= 3) {
    signals.push({
      id: 'excessive_subdomains',
      reason: `The address nests ${host.subdomainLabels.length} subdomains (${host.hostname}) — a pattern used to push the real domain out of view.`,
    });
  }

  if (SUSPICIOUS_TLDS.has(host.tld)) {
    signals.push({
      id: 'suspicious_tld',
      reason: `The “.${host.tld}” domain ending is disproportionately used for abuse.`,
      detail: host.tld,
    });
  }

  if (URL_SHORTENERS.has(host.registrableDomain) || URL_SHORTENERS.has(host.hostname)) {
    signals.push({
      id: 'url_shortener',
      reason: `“${host.hostname}” is a link shortener — the real destination is hidden.`,
      detail: host.hostname,
    });
  }

  return { url: rawUrl, host, signals, impersonatedBrand };
}

export function isShortener(hostname: string): boolean {
  const host = parseHost(hostname);
  return URL_SHORTENERS.has(host.registrableDomain) || URL_SHORTENERS.has(host.hostname);
}
