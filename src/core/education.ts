/**
 * Just-in-time micro-education cards (N14): a short, plain-language
 * explanation of each phishing technique, shown at the moment of risk
 * (pre-submit modal) and collected in the dashboard "Learn" library.
 */
import type { SignalId } from './scoring';

export interface EducationCard {
  title: string;
  /** What the technique is, in 2–3 sentences a non-expert can act on. */
  body: string;
  /** One concrete habit that defeats the technique. */
  tip: string;
}

export const EDUCATION: Partial<Record<SignalId, EducationCard>> = {
  homoglyph: {
    title: 'Lookalike characters (homoglyph attack)',
    body: 'Attackers register domains using characters from other alphabets that look identical to Latin letters — like the Cyrillic “а” in “pаypal.com”. Your eyes can\'t tell the difference, but the browser goes to a completely different site.',
    tip: 'Don\'t judge a site by how its name looks. Use a bookmark or type the address yourself.',
  },
  punycode: {
    title: 'Internationalized domain names',
    body: 'Domains can legitimately contain non-English characters, but phishers abuse this to forge brand names. Browsers show such domains as “xn--…” internally.',
    tip: 'If a familiar brand\'s address looks subtly off or contains accented letters, leave.',
  },
  typosquat: {
    title: 'Typosquatting',
    body: 'A domain one keystroke away from a real brand (“paypa1.com”, “amaz0n.com”) catches typos and skim-reading. These sites usually clone the real login page pixel-for-pixel.',
    tip: 'Check the domain character by character before entering a password — or let your password manager do it: it won\'t autofill on the wrong domain.',
  },
  brand_in_subdomain: {
    title: 'Brand-in-subdomain trick',
    body: 'In “paypal.com.secure-login.evil.tk”, the real site is “evil.tk” — everything before it is window dressing. Browsers read domains right-to-left; people read left-to-right, and attackers exploit that.',
    tip: 'The real domain is always immediately left of the final dot-suffix. Read addresses from the end.',
  },
  excessive_subdomains: {
    title: 'Deep subdomain nesting',
    body: 'Long chains of subdomains push the real domain out of the visible address bar, especially on mobile, so you only see the convincing first part.',
    tip: 'Tap or click the address bar to reveal the full address before trusting a page.',
  },
  ip_literal_host: {
    title: 'Raw IP address sites',
    body: 'Legitimate services serve users from named domains. A login or payment page addressed by a bare IP (http://203.0.113.7/login) is almost always a temporary phishing host.',
    tip: 'Never enter credentials on a page whose address is just numbers.',
  },
  userinfo_in_url: {
    title: 'The @ trick',
    body: 'In “https://paypal.com@evil.tld”, everything before the “@” is treated as a username and ignored — the browser actually visits evil.tld. The link preview, though, starts with the brand you trust.',
    tip: 'Be suspicious of any web address containing an “@”.',
  },
  suspicious_tld: {
    title: 'High-abuse domain endings',
    body: 'Some domain endings are free or near-free to register and are disproportionately used for short-lived phishing sites.',
    tip: 'A familiar brand on an unfamiliar ending (.tk, .zip, .icu…) deserves double scrutiny.',
  },
  url_shortener: {
    title: 'Shortened links',
    body: 'Link shorteners hide the destination until you arrive. Phishing emails use them to slip past filters and people.',
    tip: 'Expand short links with a preview service, or simply navigate to the service directly instead.',
  },
  cross_origin_action: {
    title: 'Form posting to a different site',
    body: 'The page you see and the server receiving your form data don\'t have to match. Phishing kits often host a convincing page anywhere and quietly post your credentials to a collection server elsewhere.',
    tip: 'PhishGuard checks this for you — when warned that a form sends data to another site, stop.',
  },
  http_action_from_https: {
    title: 'Encrypted page, unencrypted submission',
    body: 'The padlock only covers the page you loaded. A form can still send what you type over plain HTTP, readable by anyone on the network path.',
    tip: 'Treat the padlock as necessary but not sufficient; what matters is where the data goes.',
  },
  login_form_no_https: {
    title: 'Password fields without HTTPS',
    body: 'On a plain-HTTP page, everything you type travels unencrypted and can be read or altered in transit.',
    tip: 'Never type a password on a page without HTTPS.',
  },
  urgency_language: {
    title: 'Manufactured urgency',
    body: '“Your account will be suspended in 24 hours.” Urgency is the engine of phishing: it pushes you to act before you think. Real institutions rarely impose surprise deadlines for security checks.',
    tip: 'Urgency is a signal to slow down. Contact the company through its official app or site instead.',
  },
  credential_solicitation: {
    title: 'Credential fishing language',
    body: 'Messages that ask you to “verify your password”, “confirm your card with CVV”, or enter a one-time code are harvesting exactly the secrets that protect you.',
    tip: 'No legitimate service asks for your password, full card details, or recovery phrase in a message.',
  },
  payment_lure: {
    title: 'Payment and prize lures',
    body: 'Refunds you didn\'t expect, prizes you didn\'t enter for, small “redelivery fees” — all designed to get a card number or gift-card code out of you.',
    tip: 'If money appears out of nowhere, the only thing being transferred is yours.',
  },
  brand_offbrand_mismatch: {
    title: 'Brand impersonation',
    body: 'The page says “PayPal” everywhere but lives on a domain PayPal doesn\'t own. Cloning a brand\'s look takes minutes; owning its domain is the hard part — which is why the address bar is the only part you can trust.',
    tip: 'Trust the domain, not the logo.',
  },
  display_name_mismatch: {
    title: 'Display-name spoofing',
    body: 'Email display names are free text: “PayPal Support <xk9@random.ru>” shows as “PayPal Support” in most mail clients. The display name is chosen by the sender; only the address is real.',
    tip: 'Always expand the actual sender address before acting on an email.',
  },
  reply_to_divergence: {
    title: 'Reply-to hijacking',
    body: 'An email can come from one address but route your reply to another. Scammers use this to continue a conversation from an inbox they control.',
    tip: 'Check where your reply is actually addressed before sending anything sensitive.',
  },
  link_text_href_mismatch: {
    title: 'Deceptive link text',
    body: 'Link text is just text: “https://paypal.com” can link anywhere. Phishing emails rely on you reading the text instead of the destination.',
    tip: 'Hover (or long-press) links to see the real destination before clicking.',
  },
  suspicious_attachment_name: {
    title: 'Risky attachments',
    body: 'Double extensions (“invoice.pdf.exe”) and executable attachment types are how phishing escalates into malware. The icon and the name are chosen by the attacker.',
    tip: 'Never open executable attachments; verify unexpected invoices via a separate channel.',
  },
  young_domain: {
    title: 'Freshly registered domains',
    body: 'Most phishing domains are registered days before use and abandoned within weeks. A “bank” whose domain is 6 days old is not your bank.',
    tip: 'Be extra cautious with sites that have no history.',
  },
  password_reuse: {
    title: 'Password reuse across sites',
    body: 'You\'re about to enter a password here that you already use elsewhere. If this site is fake — or merely gets breached — the attacker gains entry to your other account too.',
    tip: 'Use a unique password per site; a password manager makes that effortless.',
  },
  threat_intel_hit: {
    title: 'Known-malicious site',
    body: 'This exact address has been reported and verified as phishing or malware by a live threat-intelligence feed. There is no safe way to use it.',
    tip: 'Close the tab. If you entered anything, change that password immediately from a safe device.',
  },
};
