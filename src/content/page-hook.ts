/**
 * Page-context (MAIN world) instrumentation. Runs at document_start with
 * direct access to the page's JS realm, where it:
 *
 *  - rewrites HTMLFormElement.prototype.submit() so programmatic submits
 *    fire a cancelable submit event (via requestSubmit) that the isolated-
 *    world form monitor can intercept in capture phase;
 *  - wraps fetch() and XMLHttpRequest to hold credential-shaped POSTs until
 *    the isolated world returns a verdict (window.postMessage round-trip).
 *
 * No analysis happens here; this file only surfaces submission attempts to
 * the isolated world. Keep it tiny — it runs on every page.
 */

(() => {
  const NS = '__phishguard__';
  if ((window as never as Record<string, unknown>)[NS]) return;
  (window as never as Record<string, unknown>)[NS] = true;

  const CRED_KEY_RE = /passw|passcode|pwd|otp|one[-_]?time|card[-_ ]?n|cvv|cvc|ssn|secret|seed[-_ ]?phrase|mnemonic|pin\b/i;

  function looksLikeCredentials(body: unknown): boolean {
    try {
      if (typeof body === 'string') return CRED_KEY_RE.test(body);
      if (body instanceof URLSearchParams) return CRED_KEY_RE.test(body.toString());
      if (body instanceof FormData) {
        for (const key of (body as FormData).keys()) if (CRED_KEY_RE.test(key)) return true;
      }
    } catch {
      /* opaque body */
    }
    return false;
  }

  // ---- verdict round-trip to the isolated world --------------------------
  let seq = 0;
  const pending = new Map<number, (allowed: boolean) => void>();

  window.addEventListener('message', (ev: MessageEvent) => {
    if (ev.source !== window) return;
    const d = ev.data as { pgVerdictFor?: number; allowed?: boolean } | null;
    if (d && typeof d.pgVerdictFor === 'number' && pending.has(d.pgVerdictFor)) {
      pending.get(d.pgVerdictFor)!(d.allowed === true);
      pending.delete(d.pgVerdictFor);
    }
  });

  function askVerdict(url: string, via: string): Promise<boolean> {
    return new Promise((resolve) => {
      const id = ++seq;
      pending.set(id, resolve);
      window.postMessage({ pgCheckRequest: id, url, via, pageUrl: location.href }, '*');
      // Fail-open after 4s so a broken extension never bricks the web.
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          resolve(true);
        }
      }, 4000);
    });
  }

  // ---- form.submit() ------------------------------------------------------
  const nativeSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function (this: HTMLFormElement) {
    // requestSubmit fires a cancelable submit event, which the isolated
    // world intercepts exactly like a user-initiated submit.
    try {
      if (typeof this.requestSubmit === 'function') {
        this.requestSubmit();
        return;
      }
    } catch {
      /* fall through to native */
    }
    nativeSubmit.call(this);
  };

  // ---- fetch ---------------------------------------------------------------
  const nativeFetch = window.fetch.bind(window);
  window.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<globalThis.Response> {
    try {
      const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
      const url = input instanceof Request ? input.url : String(input);
      if (method === 'POST' && looksLikeCredentials(init?.body)) {
        const allowed = await askVerdict(new URL(url, location.href).href, 'fetch');
        if (!allowed) throw new TypeError('PhishGuard blocked this request: credential-shaped POST to a high-risk destination.');
      }
    } catch (e) {
      if (e instanceof TypeError && String(e.message).includes('PhishGuard')) throw e;
      // Any instrumentation error must not break the page's fetch.
    }
    return nativeFetch(input as RequestInfo, init);
  };

  // ---- XMLHttpRequest -------------------------------------------------------
  const nativeOpen = XMLHttpRequest.prototype.open;
  const nativeSend = XMLHttpRequest.prototype.send;
  const xhrMeta = new WeakMap<XMLHttpRequest, { method: string; url: string }>();

  XMLHttpRequest.prototype.open = function (this: XMLHttpRequest, method: string, url: string | URL, ...rest: unknown[]) {
    xhrMeta.set(this, { method: String(method).toUpperCase(), url: String(url) });
    return (nativeOpen as (...a: unknown[]) => void).call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function (this: XMLHttpRequest, body?: Document | XMLHttpRequestBodyInit | null) {
    const meta = xhrMeta.get(this);
    if (meta && meta.method === 'POST' && looksLikeCredentials(body)) {
      const xhr = this;
      void askVerdict(new URL(meta.url, location.href).href, 'xhr').then((allowed) => {
        if (allowed) nativeSend.call(xhr, body);
        else xhr.dispatchEvent(new ProgressEvent('error'));
      });
      return;
    }
    return nativeSend.call(this, body);
  };
})();
