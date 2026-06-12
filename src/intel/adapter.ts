/**
 * Pluggable threat-intelligence adapter interface (M5). v1.0 ships the
 * Google Safe Browsing adapter; PhishTank/OpenPhish/URLhaus/generic REST
 * adapters slot in here post-MVP (N1).
 */

export interface TiVerdict {
  /** Feed that produced the hit. */
  source: string;
  /** e.g. SOCIAL_ENGINEERING, MALWARE. */
  threatType: string;
}

export interface TiAdapter {
  readonly name: string;
  /** True when configured (API key present, feed enabled). */
  isEnabled(): Promise<boolean>;
  /**
   * Checks a URL. Must be offline-tolerant: resolve null (no hit / unknown)
   * rather than reject when the network or feed is unavailable.
   */
  checkUrl(url: string): Promise<TiVerdict | null>;
  /** Periodic refresh of any local cache (called from chrome.alarms). */
  refresh(): Promise<void>;
}
