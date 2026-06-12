/**
 * Generic webmail heuristic adapter (N5) for self-hosted/IMAP webmail
 * frontends. Currently recognizes Roundcube and Zimbra DOM structures —
 * the two most common self-hosted clients — and activates only when their
 * characteristic markup is present, so it stays inert on ordinary sites.
 */
import type { EmailAdapter } from './index';
import { extractLinks } from './index';
import type { EmailSignals } from '../../types/messages';

export const genericWebmailAdapter: EmailAdapter = {
  // Activates on any host; extract() bails unless known webmail markup exists.
  matches: () =>
    document.querySelector('#messagebody, .rcmBody, .MsgBody, [class*="zimbra"], #rcmbtn') !== null ||
    document.body?.classList.contains('mail') === true,

  messageSelector: '#messagebody, .rcmBody, .MsgBody-html, .MsgBody',

  extract(container: HTMLElement): EmailSignals | null {
    const text = container.innerText ?? '';
    if (text.trim().length < 20) return null;

    // Roundcube: .rcmContactAddress holds "Name <addr>"; Zimbra: .ZmEmailAddress
    const senderEl = document.querySelector<HTMLElement>(
      '.rcmContactAddress, span[title*="@"].adr, .ZmEmailAddress, .MsgHdrSender',
    );
    const senderText = `${senderEl?.getAttribute('title') ?? ''} ${senderEl?.textContent ?? ''}`;
    const senderAddress = senderText.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/)?.[0] ?? '';
    const senderDisplayName = (senderEl?.textContent ?? '').replace(senderAddress, '').replace(/[<>]/g, '').trim();
    if (!senderAddress) return null;

    return {
      provider: 'unknown',
      senderDisplayName,
      senderAddress,
      replyTo: undefined,
      links: extractLinks(container),
      textSample: text.slice(0, 8000),
      attachmentNames: [...document.querySelectorAll<HTMLElement>('.attachmentslist .filename, .ZmAttachmentName')]
        .map((n) => (n.textContent ?? '').trim())
        .filter(Boolean),
    };
  },
};
