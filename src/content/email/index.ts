/**
 * Email inspector (M6): site-specific DOM adapters for Gmail and Outlook
 * Web. Scans a message lazily when it is opened, sends extracted signals
 * to the background engine, highlights deceptive links, and shows a
 * warning banner on suspicious messages.
 */
import { sendRequest, type EmailSignals, type Response } from '../../types/messages';
import { showBanner } from '../ui';
import { gmailAdapter } from './gmail';
import { outlookAdapter } from './outlook';
import { yahooAdapter } from './yahoo';
import { genericWebmailAdapter } from './generic';

export interface EmailAdapter {
  matches(hostname: string): boolean;
  /** CSS selector for an opened-message container. */
  messageSelector: string;
  extract(container: HTMLElement): EmailSignals | null;
}

// Order matters: provider-specific adapters first; the generic adapter
// self-gates on recognizable Roundcube/Zimbra markup.
const adapters: EmailAdapter[] = [gmailAdapter, outlookAdapter, yahooAdapter, genericWebmailAdapter];

const scanned = new WeakSet<HTMLElement>();

export function initEmailInspector(): void {
  // Adapter selection is deferred to DOM-ready: the generic adapter sniffs
  // page markup, which doesn't exist at document_start.
  let adapter: EmailAdapter | undefined;

  const scan = () => {
    if (!adapter) return;
    for (const container of document.querySelectorAll<HTMLElement>(adapter.messageSelector)) {
      if (scanned.has(container)) continue;
      scanned.add(container);
      const signals = adapter.extract(container);
      if (signals) void analyze(container, signals);
    }
  };

  // Webmail clients are SPAs: watch for opened messages, debounced.
  let timer: number | undefined;
  const observer = new MutationObserver(() => {
    if (timer !== undefined) return;
    timer = window.setTimeout(() => {
      timer = undefined;
      scan();
    }, 500);
  });
  const start = () => {
    adapter = adapters.find((a) => a.matches(location.hostname));
    if (!adapter) return;
    scan();
    observer.observe(document.body, { childList: true, subtree: true });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
}

async function analyze(container: HTMLElement, signals: EmailSignals): Promise<void> {
  let res: Response;
  try {
    res = await sendRequest({ kind: 'analyzeEmail', pageUrl: location.href, signals });
  } catch {
    return;
  }
  if (res.kind !== 'verdict' || res.result.verdict === 'safe') return;

  showBanner(
    `This email looks like phishing (${res.result.signals.length} warning sign${res.result.signals.length === 1 ? '' : 's'}). ` +
      res.result.signals.map((s) => s.reason).slice(0, 2).join(' '),
  );
  highlightDeceptiveLinks(container, signals);
}

/** Outlines links whose visible text claims a different domain than the href. */
function highlightDeceptiveLinks(container: HTMLElement, signals: EmailSignals): void {
  for (const anchor of container.querySelectorAll<HTMLAnchorElement>('a[href]')) {
    const text = anchor.textContent ?? '';
    const textDomain = text.match(/(?:https?:\/\/)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i)?.[1]?.toLowerCase();
    if (!textDomain) continue;
    let hrefHost = '';
    try {
      hrefHost = new URL(anchor.href).hostname.toLowerCase();
    } catch {
      continue;
    }
    const sameSite = hrefHost === textDomain || hrefHost.endsWith(`.${textDomain}`) || textDomain.endsWith(`.${hrefHost}`);
    if (!sameSite && signals.links.some((l) => l.href === anchor.href)) {
      anchor.style.outline = '2px solid #e0341b';
      anchor.style.outlineOffset = '1px';
      anchor.title = `PhishGuard: this link shows "${textDomain}" but actually opens ${hrefHost}`;
    }
  }
}

/** Shared extraction of link text/href pairs from a message body. */
export function extractLinks(body: HTMLElement): { text: string; href: string }[] {
  const links: { text: string; href: string }[] = [];
  for (const a of body.querySelectorAll<HTMLAnchorElement>('a[href]')) {
    const href = a.getAttribute('href') ?? '';
    if (!href || href.startsWith('#') || href.startsWith('mailto:')) continue;
    try {
      links.push({ text: (a.textContent ?? '').trim().slice(0, 300), href: new URL(href, location.href).href });
    } catch {
      /* unparseable href */
    }
    if (links.length >= 100) break;
  }
  return links;
}
