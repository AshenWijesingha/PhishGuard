/**
 * Content-script entry point (isolated world, document_start).
 *
 * Wires the form monitor immediately (so capture-phase interception is in
 * place before any page script runs), then performs page analysis lazily
 * after DOMContentLoaded to keep page-load overhead minimal (M17).
 */
import { hasPasswordField, hasSensitiveForm, initFormMonitor } from './forms';
import { initEmailInspector } from './email/index';
import { sendRequest, type PageSignals, type Response } from '../types/messages';
import { showBanner, showMaliciousOverlay } from './ui';

function collectPageSignals(): PageSignals {
  return {
    hasPasswordField: hasPasswordField(),
    hasSensitiveForm: hasSensitiveForm(),
    title: document.title.slice(0, 300),
    textSample: (document.body?.innerText ?? '').slice(0, 12000),
    isHttps: location.protocol === 'https:',
  };
}

let analyzed = false;

async function analyzePage(): Promise<void> {
  if (analyzed) return;
  analyzed = true;

  let res: Response;
  try {
    res = await sendRequest({ kind: 'analyzePage', url: location.href, signals: collectPageSignals() });
  } catch {
    return; // background unavailable; never break the page
  }
  if (res.kind !== 'verdict') return;
  const { verdict, signals } = res.result;

  if (verdict === 'malicious') {
    showMaliciousOverlay(
      signals,
      () => {
        void sendRequest({
          kind: 'appendAudit',
          event: {
            type: 'user_override',
            domain: location.hostname,
            url: location.href,
            verdict,
            signals: signals.map((s) => s.reason),
            userDecision: 'overridden',
          },
        });
      },
      () => {
        location.href = 'about:blank';
      },
    );
  } else if (verdict === 'high_risk' || verdict === 'suspicious') {
    const settings = await sendRequest<Response>({ kind: 'getSettings' }).catch(() => null);
    const bannerEnabled = !settings || settings.kind !== 'settings' || settings.settings.suspiciousBanner;
    if (bannerEnabled) {
      showBanner(
        signals[0]?.reason ?? 'This page shows signs of phishing. Be careful with any information you enter.',
        () => void sendRequest({ kind: 'addToAllowlist', domain: location.hostname }),
      );
    }
  }
}

// Only run the full pipeline in the top frame; subframes still get form
// interception (credential-stealing iframes are a real pattern).
initFormMonitor(() => {
  // A sensitive form appeared after initial analysis → re-analyze once.
  if (analyzed && window === window.top) {
    analyzed = false;
    void analyzePage();
  }
});

if (window === window.top) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      // Defer heavy text extraction off the critical path.
      const idle = (cb: () => void) => ('requestIdleCallback' in window ? requestIdleCallback(() => cb(), { timeout: 1500 }) : setTimeout(cb, 50));
      idle(() => void analyzePage());
    }, { once: true });
  } else {
    void analyzePage();
  }
  initEmailInspector();
}
