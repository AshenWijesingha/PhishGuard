/**
 * Yahoo Mail (mail.yahoo.com) DOM adapter (N5). Yahoo uses data-test-id
 * attributes that have been stable across redesigns.
 */
import type { EmailAdapter } from './index';
import { extractLinks } from './index';
import type { EmailSignals } from '../../types/messages';

export const yahooAdapter: EmailAdapter = {
  matches: (hostname) => hostname === 'mail.yahoo.com' || hostname.endsWith('.mail.yahoo.com'),
  messageSelector: 'div[data-test-id="message-view"], div[data-test-id="message-group-view"]',

  extract(container: HTMLElement): EmailSignals | null {
    const body = container.querySelector<HTMLElement>(
      'div[data-test-id="message-body"], div[data-test-id="message-view-body"]',
    );
    if (!body) return null;

    const fromEl = container.querySelector<HTMLElement>(
      '[data-test-id="message-from"] span[title], [data-test-id="email-pill"] span[title]',
    );
    const title = fromEl?.getAttribute('title') ?? '';
    const display = container.querySelector<HTMLElement>('[data-test-id="message-from"]')?.textContent ?? '';
    const addrMatch = (title + ' ' + display).match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/);
    const senderAddress = addrMatch?.[0] ?? '';
    const senderDisplayName = display.replace(senderAddress, '').replace(/[<>]/g, '').trim();

    return {
      provider: 'unknown',
      senderDisplayName,
      senderAddress,
      replyTo: undefined,
      links: extractLinks(body),
      textSample: (body.innerText ?? '').slice(0, 8000),
      attachmentNames: [...container.querySelectorAll<HTMLElement>('[data-test-id="attachment-card"] [title]')]
        .map((n) => n.getAttribute('title')?.trim() ?? '')
        .filter(Boolean),
    };
  },
};
