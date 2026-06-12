/**
 * Typed message contracts between content scripts, UI pages, and the
 * background service worker. Every chrome.runtime.sendMessage payload in
 * PhishGuard is one of these shapes.
 */
import type { Signal, Verdict, VerdictResult } from '../core/scoring';
import type { AuditEvent, AuditRecord } from '../storage/audit-log';
import type { Settings } from '../storage/settings';

/** Page-level signals collected by the content script's page analyzer. */
export interface PageSignals {
  hasPasswordField: boolean;
  hasSensitiveForm: boolean;
  title: string;
  /** Visible-text sample (truncated) used for on-device content heuristics. */
  textSample: string;
  isHttps: boolean;
}

/** Description of a form submission awaiting a verdict. */
export interface FormSubmitInfo {
  pageUrl: string;
  /** Fully resolved effective action URL at submit time. */
  actionUrl: string;
  method: string;
  /** Sensitive field categories present in the form. */
  sensitiveFields: string[];
  /** How the submit was initiated: native | js-submit | fetch | xhr. */
  via: string;
}

export type Request =
  | { kind: 'analyzePage'; url: string; signals?: PageSignals }
  | { kind: 'analyzeFormSubmit'; info: FormSubmitInfo }
  | { kind: 'analyzeEmail'; pageUrl: string; signals: EmailSignals }
  | { kind: 'getTabVerdict'; tabId?: number }
  | { kind: 'getAuditLog'; filter?: AuditFilter }
  | { kind: 'verifyAuditLog' }
  | { kind: 'appendAudit'; event: AuditEvent }
  | { kind: 'getLists' }
  | { kind: 'addToAllowlist'; domain: string }
  | { kind: 'removeFromAllowlist'; domain: string }
  | { kind: 'addToBlocklist'; domain: string }
  | { kind: 'removeFromBlocklist'; domain: string }
  | { kind: 'getSettings' }
  | { kind: 'updateSettings'; settings: Partial<Settings> }
  | { kind: 'reportPhishing'; url: string; signals: Signal[] };

export interface AuditFilter {
  text?: string;
  eventType?: string;
  verdict?: Verdict;
  since?: number;
  until?: number;
  limit?: number;
}

/** Signals extracted from an opened webmail message by an email adapter. */
export interface EmailSignals {
  provider: 'gmail' | 'outlook' | 'unknown';
  senderDisplayName: string;
  senderAddress: string;
  replyTo?: string;
  /** Each link in the message body: anchor text vs. real destination. */
  links: { text: string; href: string }[];
  /** Visible-text sample for content heuristics. */
  textSample: string;
  attachmentNames: string[];
}

export type Response =
  | { kind: 'verdict'; result: VerdictResult }
  | { kind: 'auditLog'; records: AuditRecord[] }
  | { kind: 'auditVerify'; ok: boolean; brokenAt?: number }
  | { kind: 'lists'; allowlist: string[]; blocklist: string[] }
  | { kind: 'settings'; settings: Settings }
  | { kind: 'ok' }
  | { kind: 'error'; message: string };

export function sendRequest<T extends Response>(req: Request): Promise<T> {
  return chrome.runtime.sendMessage(req);
}
