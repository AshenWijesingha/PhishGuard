/**
 * Outlook Web (outlook.live.com / outlook.office.com) DOM adapter.
 * Outlook uses ARIA roles and stable automation ids more than Gmail, so we
 * anchor on those.
 */
import type { EmailAdapter } from './index';
import { extractLinks } from './index';
import type { EmailSignals } from '../../types/messages';

export const outlookAdapter: EmailAdapter = {
  matches: (hostname) =>
    hostname === 'outlook.live.com' || hostname === 'outlook.office.com' || hostname === 'outlook.office365.com',
  messageSelector: 'div[role="region"][aria-label*="essage"], div[data-app-section="ConversationContainer"]',

  extract(container: HTMLElement): EmailSignals | null {
    const body = container.querySelector<HTMLElement>('div[aria-label="Message body"], .allowTextSelection, [role="document"]');
    if (!body) return null;

    // Sender appears as "Display Name <address@dom>" in the persona header.
    const senderSpan = container.querySelector<HTMLElement>('span[title*="@"], [data-testid="SenderPersona"] span');
    const title = senderSpan?.getAttribute('title') ?? '';
    const headerText = senderSpan?.textContent ?? '';
    const addrMatch = (title || headerText).match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/);
    const senderAddress = addrMatch?.[0] ?? '';
    const senderDisplayName = headerText.replace(/<[^>]*>/, '').replace(senderAddress, '').trim();

    if (!senderAddress && body.innerText.trim().length === 0) return null;

    return {
      provider: 'outlook',
      senderDisplayName,
      senderAddress,
      replyTo: undefined, // not exposed in the Outlook reading-pane DOM
      links: extractLinks(body),
      textSample: (body.innerText ?? '').slice(0, 8000),
      attachmentNames: [...container.querySelectorAll<HTMLElement>('[data-testid="attachment-card"] [title], .attachmentName')]
        .map((n) => n.getAttribute('title') ?? n.textContent ?? '')
        .map((s) => s.trim())
        .filter(Boolean),
    };
  },
};
