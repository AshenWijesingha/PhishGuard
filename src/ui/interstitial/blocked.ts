/**
 * Full-page interstitial shown when declarativeNetRequest redirects a
 * navigation to a blocklisted domain (M9). Overriding requires a typed
 * phrase and is recorded in the audit log.
 */
import { sendRequest } from '../../types/messages';

const params = new URLSearchParams(location.search);
const domain = params.get('blocked') ?? '';

const domainEl = document.getElementById('blocked-domain')!;
domainEl.textContent = domain || 'this site';

document.getElementById('btn-back')!.addEventListener('click', () => {
  if (history.length > 1) history.back();
  else location.href = 'about:blank';
});

const input = document.getElementById('confirm-input') as HTMLInputElement;
const proceed = document.getElementById('btn-proceed') as HTMLButtonElement;
input.addEventListener('input', () => {
  proceed.disabled = input.value.trim().toLowerCase() !== 'visit unsafe site';
});

proceed.addEventListener('click', async () => {
  await sendRequest({
    kind: 'appendAudit',
    event: {
      type: 'user_override',
      domain,
      verdict: 'malicious',
      signals: ['User overrode the blocklist interstitial with typed confirmation.'],
      userDecision: 'overridden',
    },
  });
  await sendRequest({ kind: 'removeFromBlocklist', domain });
  location.href = `https://${domain}`;
});
