/**
 * PhishGuard background service worker — the central decision engine.
 *
 * Receives analysis requests from content scripts and UI pages, combines
 * URL heuristics, content heuristics, local lists, and threat-intel into a
 * verdict, maintains the per-tab badge, keeps declarativeNetRequest rules
 * in sync with the local blocklist, and writes the audit log.
 */
import { analyzeUrl, parseHost } from '../core/url-heuristics';
import { BRANDS } from '../core/brands';
import { analyzeContent } from '../core/content-heuristics';
import { scoreSignals, type Signal, type Verdict, type VerdictResult } from '../core/scoring';
import { checkThreatIntel, refreshThreatIntel } from '../intel';
import {
  appendAudit, getAllRecords, pruneOldRecords, verifyChain, type AuditEvent,
} from '../storage/audit-log';
import {
  addToAllowlist, addToBlocklist, getAllowlist, getBlocklist,
  isAllowlisted, isBlocklisted, removeFromAllowlist, removeFromBlocklist,
} from '../storage/lists';
import { getSettings, updateSettings } from '../storage/settings';
import type { EmailSignals, FormSubmitInfo, PageSignals, Request, Response } from '../types/messages';

// ---------------------------------------------------------------------------
// Per-tab verdict state (rebuilt lazily after worker restarts)

const tabVerdicts = new Map<number, VerdictResult>();

const BADGE: Record<Verdict, { text: string; color: string }> = {
  safe: { text: '', color: '#1b5ea8' },
  suspicious: { text: '!', color: '#f5a623' },
  high_risk: { text: '!!', color: '#e0341b' },
  malicious: { text: 'X', color: '#8b0000' },
};

function setBadge(tabId: number | undefined, verdict: Verdict): void {
  if (tabId === undefined || tabId < 0) return;
  chrome.action.setBadgeText({ tabId, text: BADGE[verdict].text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE[verdict].color }).catch(() => {});
}

// ---------------------------------------------------------------------------
// Privacy helper: optionally store only a hash of the domain in the log

async function auditDomain(domain: string): Promise<string> {
  const settings = await getSettings();
  if (!settings.privacyHashDomains) return domain;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(domain));
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `sha256:${hex.slice(0, 32)}`;
}

async function logEvent(event: Omit<AuditEvent, 'domain'> & { domain: string; rawUrl?: string }): Promise<void> {
  const settings = await getSettings();
  await appendAudit({
    ...event,
    domain: await auditDomain(event.domain),
    url: settings.privacyHashDomains ? undefined : event.rawUrl ?? event.url,
  });
}

// ---------------------------------------------------------------------------
// Verdict computation

async function computeUrlVerdict(url: string, pageSignals?: PageSignals): Promise<VerdictResult> {
  const settings = await getSettings();
  const signals: Signal[] = [];

  if (await isAllowlisted(url)) {
    signals.push({ id: 'local_allowlist_hit', reason: 'You marked this site as trusted.' });
    return scoreSignals(signals, settings.weights, settings.thresholds);
  }
  if (await isBlocklisted(url)) {
    signals.push({ id: 'local_blocklist_hit', reason: 'This site is on your local blocklist.' });
  }

  const urlAnalysis = analyzeUrl(url);
  signals.push(...urlAnalysis.signals);

  if (pageSignals) {
    signals.push(
      ...analyzeContent({
        text: pageSignals.textSample,
        title: pageSignals.title,
        pageHostname: safeHostname(url),
      }),
    );
    if (pageSignals.hasPasswordField && !pageSignals.isHttps) {
      signals.push({
        id: 'login_form_no_https',
        reason: 'This page asks for a password but is not served over HTTPS — anything you type can be read in transit.',
      });
    }
    // A sensitive form on a page that already trips URL heuristics is worse.
    if (pageSignals.hasSensitiveForm && urlAnalysis.signals.length >= 2) {
      signals.push({
        id: 'sensitive_form_on_suspicious_page',
        reason: 'This page collects sensitive data while showing multiple suspicious address traits.',
      });
    }
  }

  const ti = await checkThreatIntel(url);
  if (ti) {
    signals.push({
      id: 'threat_intel_hit',
      reason: `This address is on a live phishing/malware blocklist (${ti.source}: ${ti.threatType}).`,
      detail: ti.source,
    });
    await logEvent({
      type: 'ti_hit',
      domain: safeHostname(url),
      rawUrl: url,
      verdict: 'malicious',
      signals: [`${ti.source}: ${ti.threatType}`],
    });
  }

  return scoreSignals(signals, settings.weights, settings.thresholds);
}

function safeHostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url.slice(0, 100);
  }
}

async function handleAnalyzePage(url: string, pageSignals: PageSignals | undefined, tabId?: number): Promise<VerdictResult> {
  const result = await computeUrlVerdict(url, pageSignals);
  if (tabId !== undefined) {
    tabVerdicts.set(tabId, result);
    setBadge(tabId, result.verdict);
  }
  if (result.verdict !== 'safe') {
    await logEvent({
      type: result.verdict === 'malicious' ? 'blocked_navigation' : 'flagged_visit',
      domain: safeHostname(url),
      rawUrl: url,
      verdict: result.verdict,
      score: result.score,
      signals: result.signals.map((s) => s.reason),
    });
  }
  return result;
}

async function handleFormSubmit(info: FormSubmitInfo): Promise<VerdictResult> {
  const settings = await getSettings();
  const signals: Signal[] = [];

  if (await isAllowlisted(info.actionUrl)) {
    signals.push({ id: 'local_allowlist_hit', reason: 'You marked the destination as trusted.' });
    return scoreSignals(signals, settings.weights, settings.thresholds);
  }

  // Destination URL heuristics
  const actionAnalysis = analyzeUrl(info.actionUrl);
  signals.push(...actionAnalysis.signals);

  // Cross-origin / downgrade checks (M4)
  const pageOrigin = safeOrigin(info.pageUrl);
  const actionOrigin = safeOrigin(info.actionUrl);
  const actionHost = parseHost(safeHostname(info.actionUrl));
  const pageHost = parseHost(safeHostname(info.pageUrl));

  if (pageOrigin && actionOrigin && pageOrigin !== actionOrigin && pageHost.registrableDomain !== actionHost.registrableDomain) {
    signals.push({
      id: 'cross_origin_action',
      reason: `This form sends your data to ${actionHost.hostname || info.actionUrl}, which is not the site you're viewing (${pageHost.hostname}).`,
      detail: actionHost.hostname,
      // Weighted higher when the page imitates a known brand.
      weight: actionAnalysis.impersonatedBrand ? settings.weights.cross_origin_action + 20 : undefined,
    });
  }
  if (info.pageUrl.startsWith('https:') && info.actionUrl.startsWith('http:')) {
    signals.push({
      id: 'http_action_from_https',
      reason: 'The page is encrypted (HTTPS) but the form submits over unencrypted HTTP — your input could be intercepted.',
    });
  }
  if (actionHost.isIp) {
    signals.push({
      id: 'action_to_ip',
      reason: `The form submits to a raw IP address (${actionHost.hostname}) instead of a named site.`,
      detail: actionHost.hostname,
    });
  }
  if (actionAnalysis.signals.some((s) => s.id === 'url_shortener')) {
    signals.push({
      id: 'action_to_shortener',
      reason: 'The form submits to a link-shortener address, hiding where your data actually goes.',
    });
  }

  if (await isBlocklisted(info.actionUrl)) {
    signals.push({ id: 'local_blocklist_hit', reason: 'The destination is on your local blocklist.' });
  }
  const ti = await checkThreatIntel(info.actionUrl);
  if (ti) {
    signals.push({
      id: 'threat_intel_hit',
      reason: `The form destination is on a live phishing blocklist (${ti.source}: ${ti.threatType}).`,
    });
  }

  const result = scoreSignals(signals, settings.weights, settings.thresholds);
  if (result.verdict === 'high_risk' || result.verdict === 'malicious') {
    await logEvent({
      type: 'blocked_submission',
      domain: safeHostname(info.actionUrl),
      rawUrl: info.actionUrl,
      verdict: result.verdict,
      score: result.score,
      signals: result.signals.map((s) => s.reason),
      userDecision: 'blocked',
    });
  } else if (result.verdict === 'suspicious') {
    await logEvent({
      type: 'detection',
      domain: safeHostname(info.actionUrl),
      rawUrl: info.actionUrl,
      verdict: result.verdict,
      score: result.score,
      signals: result.signals.map((s) => s.reason),
      userDecision: 'allowed',
    });
  }
  return result;
}

function safeOrigin(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return '';
  }
}

async function handleEmail(pageUrl: string, email: EmailSignals): Promise<VerdictResult> {
  const settings = await getSettings();
  const signals: Signal[] = [];

  // Display name claims a brand/address the sender address doesn't match.
  const addrDomain = email.senderAddress.split('@')[1]?.toLowerCase() ?? '';
  const display = email.senderDisplayName.toLowerCase();
  if (addrDomain && display) {
    const claimsDomain = display.match(/([a-z0-9-]+\.[a-z]{2,})/)?.[1];
    const claimedBrand = BRANDS.find((b) => display.includes(b.name));
    const addrReg = parseHost(addrDomain).registrableDomain;
    if (claimedBrand && !claimedBrand.domains.some((d) => addrReg === d || addrDomain.endsWith(`.${d}`))) {
      signals.push({
        id: 'display_name_mismatch',
        reason: `The sender calls itself “${email.senderDisplayName}” but the actual address is ${email.senderAddress}, which is not a ${claimedBrand.name} domain.`,
        detail: email.senderAddress,
      });
    } else if (claimsDomain && claimsDomain !== addrReg && parseHost(claimsDomain).registrableDomain !== addrReg) {
      signals.push({
        id: 'display_name_mismatch',
        reason: `The sender name shows “${claimsDomain}” but the message really comes from ${addrDomain}.`,
        detail: email.senderAddress,
      });
    }
  }

  if (email.replyTo) {
    const replyDomain = email.replyTo.split('@')[1]?.toLowerCase() ?? '';
    if (replyDomain && addrDomain && parseHost(replyDomain).registrableDomain !== parseHost(addrDomain).registrableDomain) {
      signals.push({
        id: 'reply_to_divergence',
        reason: `Replies go to ${email.replyTo}, a different domain than the sender (${addrDomain}) — a common interception trick.`,
        detail: email.replyTo,
      });
    }
  }

  // Link text shows one domain, href goes to another.
  for (const link of email.links.slice(0, 100)) {
    const textDomain = link.text.match(/(?:https?:\/\/)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i)?.[1]?.toLowerCase();
    if (!textDomain) continue;
    const hrefHost = safeHostname(link.href);
    if (!hrefHost) continue;
    if (parseHost(textDomain).registrableDomain !== parseHost(hrefHost).registrableDomain) {
      signals.push({
        id: 'link_text_href_mismatch',
        reason: `A link displays “${textDomain}” but actually opens ${hrefHost}.`,
        detail: link.href.slice(0, 200),
      });
      break; // one signal is enough; the content script highlights all of them
    }
  }

  for (const name of email.attachmentNames.slice(0, 30)) {
    if (/\.(exe|scr|js|vbs|bat|cmd|msi|jar|hta|ps1|lnk|iso|img)$/i.test(name) || /\.(pdf|docx?|xlsx?)\.(zip|exe|html?)$/i.test(name)) {
      signals.push({
        id: 'suspicious_attachment_name',
        reason: `Attachment “${name}” has a risky or double file extension.`,
        detail: name,
      });
      break;
    }
  }

  signals.push(...analyzeContent({ text: email.textSample, pageHostname: undefined }));

  const result = scoreSignals(signals, settings.weights, settings.thresholds);
  if (result.verdict !== 'safe') {
    await logEvent({
      type: 'detection',
      domain: addrDomain || safeHostname(pageUrl),
      verdict: result.verdict,
      score: result.score,
      signals: result.signals.map((s) => s.reason),
    });
  }
  return result;
}

// ---------------------------------------------------------------------------
// declarativeNetRequest: block navigations to blocklisted domains (M9)

const DNR_RULE_OFFSET = 1000;

async function syncBlocklistRules(): Promise<void> {
  const blocklist = await getBlocklist();
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const interstitial = chrome.runtime.getURL('blocked.html');
  const rules: chrome.declarativeNetRequest.Rule[] = blocklist.slice(0, 4000).map((domain, i) => ({
    id: DNR_RULE_OFFSET + i,
    priority: 1,
    action: {
      type: 'redirect' as chrome.declarativeNetRequest.RuleActionType,
      redirect: { url: `${interstitial}?blocked=${encodeURIComponent(domain)}` },
    },
    condition: {
      requestDomains: [domain],
      resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
    },
  }));
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map((r) => r.id),
    addRules: rules,
  });
}

// ---------------------------------------------------------------------------
// Message router

chrome.runtime.onMessage.addListener((msg: Request, sender, sendResponse: (r: Response) => void) => {
  (async (): Promise<Response> => {
    switch (msg.kind) {
      case 'analyzePage':
        return { kind: 'verdict', result: await handleAnalyzePage(msg.url, msg.signals, sender.tab?.id) };
      case 'analyzeFormSubmit':
        return { kind: 'verdict', result: await handleFormSubmit(msg.info) };
      case 'analyzeEmail':
        return { kind: 'verdict', result: await handleEmail(msg.pageUrl, msg.signals) };
      case 'getTabVerdict': {
        const tabId = msg.tabId ?? sender.tab?.id;
        const result = tabId !== undefined ? tabVerdicts.get(tabId) : undefined;
        return { kind: 'verdict', result: result ?? { verdict: 'safe', score: 0, signals: [] } };
      }
      case 'getAuditLog': {
        let records = await getAllRecords();
        const f = msg.filter;
        if (f) {
          if (f.eventType) records = records.filter((r) => r.type === f.eventType);
          if (f.verdict) records = records.filter((r) => r.verdict === f.verdict);
          if (f.since) records = records.filter((r) => r.timestamp >= f.since!);
          if (f.until) records = records.filter((r) => r.timestamp <= f.until!);
          if (f.text) {
            const t = f.text.toLowerCase();
            records = records.filter(
              (r) => r.domain.toLowerCase().includes(t) || (r.url ?? '').toLowerCase().includes(t) || r.signals.some((s) => s.toLowerCase().includes(t)),
            );
          }
        }
        records.sort((a, b) => b.seq - a.seq);
        if (f?.limit) records = records.slice(0, f.limit);
        return { kind: 'auditLog', records };
      }
      case 'verifyAuditLog': {
        const v = await verifyChain();
        return { kind: 'auditVerify', ok: v.ok, brokenAt: v.brokenAt };
      }
      case 'appendAudit':
        await logEvent({ ...msg.event, rawUrl: msg.event.url });
        return { kind: 'ok' };
      case 'getLists':
        return { kind: 'lists', allowlist: await getAllowlist(), blocklist: await getBlocklist() };
      case 'addToAllowlist':
        await addToAllowlist(msg.domain);
        await logEvent({ type: 'allowlist_add', domain: msg.domain, signals: [], userDecision: 'allowed' });
        return { kind: 'ok' };
      case 'removeFromAllowlist':
        await removeFromAllowlist(msg.domain);
        return { kind: 'ok' };
      case 'addToBlocklist':
        await addToBlocklist(msg.domain);
        await syncBlocklistRules();
        await logEvent({ type: 'blocklist_add', domain: msg.domain, signals: [], userDecision: 'blocked' });
        return { kind: 'ok' };
      case 'removeFromBlocklist':
        await removeFromBlocklist(msg.domain);
        await syncBlocklistRules();
        return { kind: 'ok' };
      case 'getSettings':
        return { kind: 'settings', settings: await getSettings() };
      case 'updateSettings':
        return { kind: 'settings', settings: await updateSettings(msg.settings) };
      case 'reportPhishing':
        await logEvent({
          type: 'report_phishing',
          domain: safeHostname(msg.url),
          rawUrl: msg.url,
          signals: msg.signals.map((s) => s.reason),
          userDecision: 'reported',
        });
        return { kind: 'ok' };
    }
  })()
    .then(sendResponse)
    .catch((e: unknown) => sendResponse({ kind: 'error', message: String(e) }));
  return true; // async response
});

// ---------------------------------------------------------------------------
// Alarms: TI refresh + log retention

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create('ti-refresh', { periodInMinutes: 30, delayInMinutes: 1 });
  chrome.alarms.create('log-prune', { periodInMinutes: 24 * 60, delayInMinutes: 5 });
  void syncBlocklistRules();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'ti-refresh') void refreshThreatIntel();
  if (alarm.name === 'log-prune') {
    void getSettings().then((s) => pruneOldRecords(s.logRetentionDays));
  }
});

chrome.tabs.onRemoved.addListener((tabId) => tabVerdicts.delete(tabId));
