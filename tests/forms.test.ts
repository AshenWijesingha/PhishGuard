// @vitest-environment happy-dom
/**
 * Integration-style tests: sensitive-field detection and effective-action
 * resolution against the bundled benign/phishing HTML fixtures (M2/M4).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { effectiveAction, sensitiveCategories } from '../src/content/forms';
import { analyzeContent } from '../src/core/content-heuristics';

const fixture = (name: string) => readFileSync(join(__dirname, 'fixtures', name), 'utf8');

beforeAll(() => {
  // forms.ts touches chrome.runtime only at call time; provide a stub anyway.
  (globalThis as never as { chrome: unknown }).chrome = { runtime: { sendMessage: async () => ({}) } };
});

function loadForm(html: string): HTMLFormElement {
  document.body.innerHTML = html.replace(/^[\s\S]*<body>|<\/body>[\s\S]*$/g, '');
  return document.querySelector('form')!;
}

describe('sensitive-field detection (M2)', () => {
  it('detects password + autocomplete fields in the benign fixture', () => {
    const form = loadForm(fixture('benign-login.html'));
    const cats = sensitiveCategories(form);
    expect(cats).toContain('password');
  });

  it('detects password, card, CVV, and OTP fields in the phishing fixture', () => {
    const form = loadForm(fixture('phishing-login.html'));
    const cats = sensitiveCategories(form);
    expect(cats).toEqual(expect.arrayContaining(['password', 'card number', 'card security code', 'one-time code']));
  });

  it('ignores forms with no sensitive fields', () => {
    document.body.innerHTML = '<form><input type="search" name="q" /></form>';
    expect(sensitiveCategories(document.querySelector('form')!)).toEqual([]);
  });

  it('detects seed-phrase fields via label heuristics', () => {
    document.body.innerHTML = '<form><label for="sp">Recovery phrase</label><textarea id="sp" name="words"></textarea></form>';
    expect(sensitiveCategories(document.querySelector('form')!)).toContain('seed phrase');
  });
});

describe('effective action resolution (M4)', () => {
  it('resolves an absolute cross-origin action', () => {
    const form = loadForm(fixture('phishing-login.html'));
    const { url, method } = effectiveAction(form);
    expect(url).toBe('https://collect.evil-harvest.tk/grab');
    expect(method).toBe('post');
  });

  it('resolves empty action to the current page', () => {
    document.body.innerHTML = '<form><input type="password" name="p" /></form>';
    const { url } = effectiveAction(document.querySelector('form')!);
    expect(url).toBe(location.href);
  });

  it('prefers the submitter formaction', () => {
    document.body.innerHTML =
      '<form action="/a"><input type="password" name="p" /><button id="b" formaction="https://other.example/steal" formmethod="post">Go</button></form>';
    const { url, method } = effectiveAction(document.querySelector('form')!, document.getElementById('b'));
    expect(url).toBe('https://other.example/steal');
    expect(method).toBe('post');
  });
});

describe('fixture content heuristics (integration)', () => {
  it('phishing fixture trips multiple content signals', () => {
    document.body.innerHTML = fixture('phishing-login.html');
    const ids = analyzeContent({
      text: document.body.textContent ?? '',
      title: 'PayPal — Verify Your Account',
      pageHostname: 'secure-paypal-verify.example.tk',
    }).map((s) => s.id);
    expect(ids).toContain('urgency_language');
    expect(ids).toContain('credential_solicitation');
    expect(ids).toContain('brand_offbrand_mismatch');
  });

  it('benign fixture stays quiet', () => {
    document.body.innerHTML = fixture('benign-login.html');
    const signals = analyzeContent({
      text: document.body.textContent ?? '',
      title: 'Example Shop — Sign in',
      pageHostname: 'shop.example.com',
    });
    expect(signals).toEqual([]);
  });
});
