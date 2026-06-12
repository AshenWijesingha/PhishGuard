/**
 * In-page warning UI: blocking pre-submit modal (M10), non-blocking
 * suspicious banner, and full-page interstitial overlay for malicious
 * pages detected after navigation started.
 *
 * Everything is built with createElement/textContent — never innerHTML —
 * so page- or email-controlled strings cannot inject markup into our UI,
 * and it all lives in a closed shadow root to resist page CSS/JS tampering.
 */
import type { Signal, Verdict } from '../core/scoring';
import { VERDICT_LABEL } from '../core/scoring';

const Z = '2147483647';

function makeHost(id: string): { host: HTMLElement; root: ShadowRoot } {
  const host = document.createElement('div');
  host.id = id;
  host.style.cssText = 'all:initial; position:fixed; z-index:' + Z + ';';
  const root = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
    .modal-backdrop { position: fixed; inset: 0; background: rgba(10,12,16,.72); display: flex; align-items: center; justify-content: center; }
    .card { background: #fff; color: #16191f; border-radius: 12px; max-width: 560px; width: calc(100vw - 48px); box-shadow: 0 18px 60px rgba(0,0,0,.45); overflow: hidden; }
    .card-head { padding: 18px 22px; color: #fff; font-size: 17px; font-weight: 700; display: flex; gap: 10px; align-items: center; }
    .card-head.high_risk { background: #c62f17; }
    .card-head.malicious { background: #7a0c0c; }
    .card-body { padding: 18px 22px; font-size: 14px; line-height: 1.5; max-height: 50vh; overflow: auto; }
    .lead { margin: 0 0 12px; }
    ul.reasons { margin: 0 0 8px; padding-left: 20px; }
    ul.reasons li { margin-bottom: 8px; }
    .dest { font-family: ui-monospace, monospace; background: #f4f5f7; padding: 2px 6px; border-radius: 4px; word-break: break-all; }
    .card-foot { padding: 14px 22px 20px; display: flex; flex-direction: column; gap: 10px; }
    button { font-size: 14px; border-radius: 8px; padding: 11px 16px; cursor: pointer; border: 1px solid #c9ced6; background: #fff; }
    button.primary { background: #1b5ea8; border-color: #1b5ea8; color: #fff; font-weight: 700; }
    button.danger-link { border: none; background: none; color: #8a8f98; text-decoration: underline; padding: 6px; font-size: 13px; }
    button:focus-visible { outline: 3px solid #1b5ea8; outline-offset: 2px; }
    input[type=text] { font-size: 14px; padding: 10px 12px; border: 1px solid #c9ced6; border-radius: 8px; width: 100%; }
    .confirm-row { display: none; flex-direction: column; gap: 8px; }
    .confirm-row.visible { display: flex; }
    .banner { position: fixed; top: 0; left: 0; right: 0; background: #fff7e6; color: #5c4500; border-bottom: 2px solid #f5a623; padding: 10px 16px; font-size: 13px; display: flex; gap: 12px; align-items: center; }
    .banner button { padding: 5px 10px; font-size: 12px; }
    .overlay { position: fixed; inset: 0; background: #7a0c0c; color: #fff; display: flex; align-items: center; justify-content: center; }
    .overlay .card { background: #fff; }
    @media (prefers-reduced-motion: no-preference) { .card { animation: pg-in .15s ease-out; } }
    @keyframes pg-in { from { transform: scale(.97); opacity: 0; } }
  `;
  root.appendChild(style);
  return { host, root };
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

export interface ModalOptions {
  verdict: Verdict;
  signals: Signal[];
  destination: string;
  /** Required typed phrase to override a Confirmed Malicious verdict. */
  overridePhrase?: string;
}

/**
 * Shows the blocking pre-submit modal. Resolves true only if the user
 * explicitly overrides; Cancel (default, focused) and Escape resolve false.
 */
export function showBlockingModal(opts: ModalOptions): Promise<boolean> {
  return new Promise((resolve) => {
    const { host, root } = makeHost('phishguard-modal');
    const done = (allowed: boolean) => {
      host.remove();
      document.removeEventListener('keydown', onKey, true);
      resolve(allowed);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        done(false);
      }
    };
    document.addEventListener('keydown', onKey, true);

    const backdrop = el('div', 'modal-backdrop');
    backdrop.setAttribute('role', 'alertdialog');
    backdrop.setAttribute('aria-modal', 'true');
    backdrop.setAttribute('aria-label', 'PhishGuard security warning');

    const card = el('div', 'card');
    const head = el('div', `card-head ${opts.verdict}`);
    head.append(el('span', undefined, '⚠'), el('span', undefined, `PhishGuard blocked this submission — ${VERDICT_LABEL[opts.verdict]}`));

    const body = el('div', 'card-body');
    const lead = el('p', 'lead');
    lead.append('This form was about to send your information to ');
    lead.append(el('span', 'dest', opts.destination));
    lead.append('. PhishGuard stopped it because:');
    const reasons = el('ul', 'reasons');
    for (const s of opts.signals) reasons.appendChild(el('li', undefined, s.reason));
    body.append(lead, reasons);

    const foot = el('div', 'card-foot');
    const cancel = el('button', 'primary', 'Go back — don’t send (recommended)');
    cancel.addEventListener('click', () => done(false));

    const confirmRow = el('div', 'confirm-row');
    const proceed = el('button', 'danger-link', 'Proceed anyway (not recommended)');

    if (opts.verdict === 'malicious' && opts.overridePhrase) {
      const phrase = opts.overridePhrase;
      const label = el('label', undefined, `This destination is confirmed malicious. To override, type “${phrase}”:`);
      const input = el('input');
      input.type = 'text';
      input.setAttribute('aria-label', 'Override confirmation phrase');
      const go = el('button', undefined, 'Send anyway');
      go.disabled = true;
      input.addEventListener('input', () => {
        go.disabled = input.value.trim().toLowerCase() !== phrase.toLowerCase();
      });
      go.addEventListener('click', () => done(true));
      confirmRow.append(label, input, go);
      proceed.addEventListener('click', () => {
        confirmRow.classList.add('visible');
        input.focus();
      });
    } else {
      proceed.addEventListener('click', () => done(true));
    }

    foot.append(cancel, confirmRow, proceed);
    card.append(head, body, foot);
    backdrop.appendChild(card);
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) done(false);
    });
    root.appendChild(backdrop);
    (document.body ?? document.documentElement).appendChild(host);
    cancel.focus();
  });
}

let bannerHost: HTMLElement | undefined;

/** Non-blocking warning banner for Suspicious verdicts. */
export function showBanner(message: string, onAllowSite?: () => void): void {
  if (bannerHost?.isConnected) return;
  const { host, root } = makeHost('phishguard-banner');
  bannerHost = host;
  const bar = el('div', 'banner');
  bar.setAttribute('role', 'alert');
  bar.append(el('span', undefined, '⚠ PhishGuard: ' + message));
  if (onAllowSite) {
    const allow = el('button', undefined, 'This is a false positive');
    allow.addEventListener('click', () => {
      onAllowSite();
      host.remove();
    });
    bar.appendChild(allow);
  }
  const close = el('button', undefined, 'Dismiss');
  close.addEventListener('click', () => host.remove());
  bar.appendChild(close);
  root.appendChild(bar);
  (document.body ?? document.documentElement).appendChild(host);
}

/** Full-page overlay for malicious pages detected post-navigation. */
export function showMaliciousOverlay(signals: Signal[], onProceed: () => void, onLeave: () => void): void {
  const { host, root } = makeHost('phishguard-overlay');
  const overlay = el('div', 'overlay');
  overlay.setAttribute('role', 'alertdialog');
  overlay.setAttribute('aria-modal', 'true');
  const card = el('div', 'card');
  const head = el('div', 'card-head malicious');
  head.append(el('span', undefined, '⛔'), el('span', undefined, 'PhishGuard: this site is confirmed malicious'));
  const body = el('div', 'card-body');
  body.appendChild(el('p', 'lead', 'This page matches a live phishing or malware blocklist. Do not enter any information here.'));
  const reasons = el('ul', 'reasons');
  for (const s of signals) reasons.appendChild(el('li', undefined, s.reason));
  body.appendChild(reasons);
  const foot = el('div', 'card-foot');
  const leave = el('button', 'primary', 'Leave this site (recommended)');
  leave.addEventListener('click', () => {
    onLeave();
  });
  const proceed = el('button', 'danger-link', 'Ignore the warning and continue');
  proceed.addEventListener('click', () => {
    host.remove();
    onProceed();
  });
  foot.append(leave, proceed);
  card.append(head, body, foot);
  overlay.appendChild(card);
  root.appendChild(overlay);
  (document.body ?? document.documentElement).appendChild(host);
  leave.focus();
}
