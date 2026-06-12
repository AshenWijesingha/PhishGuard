/**
 * Form monitor (M2/M3/M4, isolated world).
 *
 *  - Identifies sensitive fields (password, payment card, OTP, SSN, seed
 *    phrase) via input types, autocomplete attributes, and name/label
 *    heuristics; tracks dynamically injected forms with a debounced
 *    MutationObserver.
 *  - Intercepts submit events in capture phase BEFORE any network request:
 *    sensitive submissions are always prevented first, evaluated by the
 *    background engine, then re-fired via the isolated world's native
 *    form.submit() (which the MAIN-world wrapper cannot see) when allowed.
 *  - Relays credential-shaped fetch/XHR checks from the page hook.
 */
import { sendRequest, type FormSubmitInfo, type Response } from '../types/messages';
import type { VerdictResult } from '../core/scoring';
import { showBlockingModal } from './ui';

const SENSITIVE_AUTOCOMPLETE = new Set([
  'current-password', 'new-password', 'one-time-code',
  'cc-number', 'cc-csc', 'cc-exp', 'cc-exp-month', 'cc-exp-year', 'cc-name',
]);

const FIELD_PATTERNS: { category: string; re: RegExp }[] = [
  { category: 'password', re: /passw|passcode|pwd/i },
  { category: 'card number', re: /card[-_ ]?(num|no)|cc[-_ ]?num|pan\b|credit[-_ ]?card/i },
  { category: 'card security code', re: /cvv|cvc|csc|security[-_ ]?code/i },
  { category: 'one-time code', re: /\botp\b|one[-_ ]?time|2fa|mfa[-_ ]?code|verification[-_ ]?code|auth[-_ ]?code/i },
  { category: 'SSN', re: /\bssn\b|social[-_ ]?security/i },
  { category: 'seed phrase', re: /seed[-_ ]?phrase|recovery[-_ ]?phrase|mnemonic|secret[-_ ]?words/i },
];

function labelTextFor(input: HTMLElement): string {
  const id = input.id;
  let text = '';
  if (id) {
    try {
      const label = document.querySelector(`label[for="${CSS.escape(id)}"]`);
      if (label) text += ' ' + (label.textContent ?? '');
    } catch { /* invalid id */ }
  }
  const wrapping = input.closest('label');
  if (wrapping) text += ' ' + (wrapping.textContent ?? '');
  return text.slice(0, 300);
}

/** Returns the sensitive-field categories present in a form (empty = not sensitive). */
export function sensitiveCategories(form: HTMLFormElement): string[] {
  const cats = new Set<string>();
  for (const elem of form.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('input, textarea')) {
    const type = (elem.getAttribute('type') ?? 'text').toLowerCase();
    if (type === 'hidden' || type === 'submit' || type === 'button' || type === 'checkbox' || type === 'radio') continue;
    if (type === 'password') {
      cats.add('password');
      continue;
    }
    const autocomplete = (elem.getAttribute('autocomplete') ?? '').toLowerCase();
    if (SENSITIVE_AUTOCOMPLETE.has(autocomplete)) {
      cats.add(autocomplete.startsWith('cc-') ? 'payment card' : autocomplete === 'one-time-code' ? 'one-time code' : 'password');
      continue;
    }
    const haystack = `${elem.name} ${elem.id} ${elem.getAttribute('placeholder') ?? ''} ${elem.getAttribute('aria-label') ?? ''} ${labelTextFor(elem)}`;
    for (const { category, re } of FIELD_PATTERNS) {
      if (re.test(haystack)) cats.add(category);
    }
  }
  return [...cats];
}

/** Resolves the effective submission destination at submit time (M4). */
export function effectiveAction(form: HTMLFormElement, submitter?: HTMLElement | null): { url: string; method: string } {
  // formaction on the submitter wins over the form's action.
  const formaction = submitter?.getAttribute('formaction');
  const rawAction = formaction ?? form.getAttribute('action') ?? '';
  const method = (submitter?.getAttribute('formmethod') ?? form.getAttribute('method') ?? 'get').toLowerCase();
  let url: string;
  try {
    url = new URL(rawAction, document.baseURI).href; // empty action → current page
  } catch {
    url = location.href;
  }
  return { url, method };
}

// Forms whose pending submission has been approved; native submit() below
// bypasses the submit event, so no re-entry happens.
const approvedOnce = new WeakSet<HTMLFormElement>();

async function evaluateSubmission(info: FormSubmitInfo): Promise<{ allowed: boolean; result: VerdictResult }> {
  let result: VerdictResult;
  try {
    const res = await sendRequest<Response>({ kind: 'analyzeFormSubmit', info });
    result = res.kind === 'verdict' ? res.result : { verdict: 'safe', score: 0, signals: [] };
  } catch {
    // Background unavailable (e.g. extension reload): fail open.
    return { allowed: true, result: { verdict: 'safe', score: 0, signals: [] } };
  }

  if (result.verdict === 'high_risk' || result.verdict === 'malicious') {
    const destination = (() => {
      try {
        return new URL(info.actionUrl).host;
      } catch {
        return info.actionUrl;
      }
    })();
    const allowed = await showBlockingModal({
      verdict: result.verdict,
      signals: result.signals,
      destination,
      overridePhrase: result.verdict === 'malicious' ? 'send my data anyway' : undefined,
    });
    if (allowed) {
      void sendRequest({
        kind: 'appendAudit',
        event: {
          type: 'user_override',
          domain: destination,
          url: info.actionUrl,
          verdict: result.verdict,
          score: result.score,
          signals: result.signals.map((s) => s.reason),
          userDecision: 'overridden',
        },
      });
    }
    return { allowed, result };
  }
  return { allowed: true, result };
}

/** SHA-256 hex of the form's first non-empty password value (N10). */
async function passwordDigest(form: HTMLFormElement): Promise<string | undefined> {
  const field = form.querySelector<HTMLInputElement>('input[type=password]');
  const value = field?.value ?? '';
  if (value.length < 4) return undefined;
  try {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return undefined;
  }
}

function onSubmitCapture(event: SubmitEvent): void {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  if (approvedOnce.has(form)) {
    approvedOnce.delete(form);
    return;
  }
  const categories = sensitiveCategories(form);
  if (categories.length === 0) return;

  // Block synchronously — the verdict is computed async, and the submission
  // is replayed with the isolated world's pristine native submit().
  event.preventDefault();
  event.stopImmediatePropagation();
  const { url, method } = effectiveAction(form, event.submitter);

  void (async () => {
    const pwdDigest = await passwordDigest(form);
    const { allowed } = await evaluateSubmission({
      pageUrl: location.href,
      actionUrl: url,
      method,
      sensitiveFields: categories,
      via: 'native',
      pwdDigest,
    });
    if (allowed && form.isConnected) {
      // Remember the password→origin pairing so future reuse on a
      // different origin can be flagged (stored salted, never plaintext).
      if (pwdDigest) {
        void sendRequest({ kind: 'recordPasswordUse', pwdDigest, origin: location.origin }).catch(() => {});
      }
      approvedOnce.add(form);
      HTMLFormElement.prototype.submit.call(form);
    }
  })();
}

/** Relay credential-shaped fetch/XHR checks from the MAIN-world hook. */
function onPageHookMessage(ev: MessageEvent): void {
  if (ev.source !== window) return;
  const d = ev.data as { pgCheckRequest?: number; url?: string; via?: string } | null;
  if (!d || typeof d.pgCheckRequest !== 'number' || typeof d.url !== 'string') return;
  void evaluateSubmission({
    pageUrl: location.href,
    actionUrl: d.url,
    method: 'post',
    sensitiveFields: ['credential-shaped request body'],
    via: d.via ?? 'fetch',
  }).then(({ allowed }) => {
    window.postMessage({ pgVerdictFor: d.pgCheckRequest, allowed }, '*');
  });
}

/** Count of sensitive forms currently known on the page (for the analyzer). */
let sensitiveFormCount = 0;
export function hasSensitiveForm(): boolean {
  return sensitiveFormCount > 0;
}
export function hasPasswordField(): boolean {
  return document.querySelector('input[type=password]') !== null;
}

function rescanForms(): void {
  let count = 0;
  for (const form of document.querySelectorAll('form')) {
    if (sensitiveCategories(form).length > 0) count++;
  }
  sensitiveFormCount = count;
}

export function initFormMonitor(onChange?: () => void): void {
  window.addEventListener('submit', onSubmitCapture, true);
  window.addEventListener('message', onPageHookMessage);

  // Debounced MutationObserver for dynamically injected forms (M2).
  let timer: number | undefined;
  const observer = new MutationObserver(() => {
    if (timer !== undefined) return;
    timer = window.setTimeout(() => {
      timer = undefined;
      const before = sensitiveFormCount;
      rescanForms();
      if (sensitiveFormCount !== before) onChange?.();
    }, 250);
  });
  const start = () => {
    rescanForms();
    observer.observe(document.documentElement, { childList: true, subtree: true });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
}
