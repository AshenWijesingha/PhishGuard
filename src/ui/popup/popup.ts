/**
 * Toolbar popup (M15): current-page verdict, plain-language signal
 * breakdown, and one-click report / allowlist / blocklist actions.
 */
import { sendRequest, type Response } from '../../types/messages';
import { VERDICT_LABEL, type VerdictResult } from '../../core/scoring';

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

async function activeTab(): Promise<chrome.tabs.Tab | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function init(): Promise<void> {
  const tab = await activeTab();
  const url = tab?.url ?? '';
  let hostname = '';
  try {
    hostname = new URL(url).hostname;
  } catch {
    /* chrome:// pages etc. */
  }
  $('site').textContent = hostname || '(no analyzable page)';

  let result: VerdictResult = { verdict: 'safe', score: 0, signals: [] };
  if (tab?.id !== undefined) {
    const res = await sendRequest<Response>({ kind: 'getTabVerdict', tabId: tab.id }).catch(() => null);
    if (res?.kind === 'verdict') result = res.result;
  }

  const pill = $('verdict-pill');
  pill.className = `pill ${result.verdict}`;
  pill.textContent = VERDICT_LABEL[result.verdict];

  const signalsBox = $('signals');
  signalsBox.textContent = '';
  if (result.signals.length === 0) {
    const ok = document.createElement('div');
    ok.className = 'sig';
    ok.style.borderLeftColor = '#2e8540';
    ok.textContent = 'No phishing signals detected on this page.';
    signalsBox.appendChild(ok);
  }
  for (const s of result.signals) {
    const div = document.createElement('div');
    div.className = 'sig';
    div.textContent = s.reason;
    signalsBox.appendChild(div);
  }

  const disableIfNoSite = (btn: HTMLElement) => {
    if (!hostname) (btn as HTMLButtonElement).disabled = true;
  };
  disableIfNoSite($('btn-allow'));
  disableIfNoSite($('btn-report'));
  disableIfNoSite($('btn-block'));

  $('btn-allow').addEventListener('click', async () => {
    await sendRequest({ kind: 'addToAllowlist', domain: hostname });
    window.close();
  });
  $('btn-report').addEventListener('click', async () => {
    await sendRequest({ kind: 'reportPhishing', url, signals: result.signals });
    $('btn-report').textContent = 'Reported ✓';
  });
  $('btn-block').addEventListener('click', async () => {
    await sendRequest({ kind: 'addToBlocklist', domain: hostname });
    window.close();
  });
  $('open-dashboard').addEventListener('click', (e) => {
    e.preventDefault();
    void chrome.runtime.openOptionsPage();
  });
}

void init();
