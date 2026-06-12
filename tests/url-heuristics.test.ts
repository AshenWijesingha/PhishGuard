import { describe, expect, it } from 'vitest';
import { analyzeUrl, decodeLabel, isIpLiteral, levenshtein, parseHost } from '../src/core/url-heuristics';
import { hasConfusables, toSkeleton } from '../src/core/confusables';

const signalIds = (url: string) => analyzeUrl(url).signals.map((s) => s.id);

describe('parseHost', () => {
  it('extracts registrable domain', () => {
    expect(parseHost('www.paypal.com').registrableDomain).toBe('paypal.com');
    expect(parseHost('a.b.example.co.uk').registrableDomain).toBe('example.co.uk');
    expect(parseHost('login.secure.bank.example.com').subdomainLabels).toEqual(['login', 'secure', 'bank']);
  });
  it('recognizes IP literals', () => {
    expect(isIpLiteral('192.168.1.1')).toBe(true);
    expect(isIpLiteral('0x7f000001')).toBe(true);
    expect(isIpLiteral('paypal.com')).toBe(false);
  });
});

describe('punycode decoding', () => {
  it('decodes xn-- labels', () => {
    // xn--pypal-4ve.com is "pаypal" with Cyrillic а
    expect(decodeLabel('xn--pypal-4ve')).toContain('p');
    expect(decodeLabel('xn--mnchen-3ya')).toBe('münchen');
    expect(decodeLabel('plain')).toBe('plain');
  });
});

describe('confusable skeleton', () => {
  it('maps Cyrillic lookalikes to ASCII', () => {
    expect(toSkeleton('pаypal.com')).toBe('paypal.com'); // Cyrillic а
    expect(hasConfusables('pаypal.com')).toBe(true);
    expect(hasConfusables('paypal.com')).toBe(false);
  });
});

describe('analyzeUrl heuristics (M1)', () => {
  it('flags homoglyph brand impersonation', () => {
    // Cyrillic "а" in paypal
    const ids = signalIds('https://xn--pypal-4ve.com/login');
    expect(ids).toContain('punycode');
    expect(ids).toContain('homoglyph');
  });

  it('flags typosquats one edit away from a brand', () => {
    expect(signalIds('https://paypa1.com/login')).toContain('typosquat');
    expect(signalIds('https://amaz0n.com')).toContain('typosquat');
    expect(signalIds('https://microsofft.com')).toContain('typosquat');
  });

  it('does not flag the legitimate brand domains', () => {
    expect(signalIds('https://www.paypal.com/signin')).toEqual([]);
    expect(signalIds('https://accounts.google.com')).toEqual([]);
  });

  it('flags brand names buried in subdomains', () => {
    const ids = signalIds('https://paypal.com.secure-login.example.tk/');
    expect(ids).toContain('brand_in_subdomain');
    expect(ids).toContain('suspicious_tld');
  });

  it('flags excessive subdomain nesting', () => {
    expect(signalIds('https://a.b.c.d.example.com/')).toContain('excessive_subdomains');
  });

  it('flags IP-literal hosts', () => {
    expect(signalIds('http://192.168.0.10/login')).toContain('ip_literal_host');
  });

  it('flags userinfo-in-URL tricks', () => {
    expect(signalIds('https://paypal.com%40evil.example/'.replace('%40', '@'))).toContain('userinfo_in_url');
  });

  it('flags URL shorteners', () => {
    expect(signalIds('https://bit.ly/3abcde')).toContain('url_shortener');
  });

  it('flags plain HTTP', () => {
    expect(signalIds('http://example.com/')).toContain('insecure_http');
  });
});

describe('levenshtein', () => {
  it('computes edit distance', () => {
    expect(levenshtein('paypal', 'paypal')).toBe(0);
    expect(levenshtein('paypal', 'paypa1')).toBe(1);
    expect(levenshtein('google', 'goggle')).toBe(1);
    expect(levenshtein('abc', 'xyz')).toBe(3);
  });
});
