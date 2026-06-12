/**
 * Gmail DOM adapter. Gmail's class names are obfuscated but stable for
 * years; selectors are centralized here so a UI change is a one-file fix.
 *
 *  - Opened message container: div.adn (one per message in the thread view)
 *  - Sender: .gD has name + email attribute; .go holds the address text
 *  - Body: .a3s
 *  - Attachments: .aZo / .aQH spans with download names
 */
import type { EmailAdapter } from './index';
import { extractLinks } from './index';
import type { EmailSignals } from '../../types/messages';

export const gmailAdapter: EmailAdapter = {
  matches: (hostname) => hostname === 'mail.google.com',
  messageSelector: 'div.adn',

  extract(container: HTMLElement): EmailSignals | null {
    const senderEl = container.querySelector<HTMLElement>('.gD');
    const body = container.querySelector<HTMLElement>('.a3s');
    if (!body) return null;

    const senderDisplayName = (senderEl?.getAttribute('name') ?? senderEl?.textContent ?? '').trim();
    const senderAddress = (senderEl?.getAttribute('email') ?? container.querySelector('.go')?.textContent?.replace(/[<>]/g, '') ?? '').trim();

    // Gmail surfaces reply-to in the expanded details pane when divergent.
    const replyTo = container
      .querySelector<HTMLElement>('.ajv [email], .iw [email]')
      ?.getAttribute('email') ?? undefined;

    const attachmentNames = [...container.querySelectorAll<HTMLElement>('.aZo .aV3, .aQH .aV3, span.aZp')]
      .map((n) => (n.textContent ?? '').trim())
      .filter(Boolean);

    return {
      provider: 'gmail',
      senderDisplayName,
      senderAddress,
      replyTo: replyTo && replyTo !== senderAddress ? replyTo : undefined,
      links: extractLinks(body),
      textSample: (body.innerText ?? '').slice(0, 8000),
      attachmentNames,
    };
  },
};
