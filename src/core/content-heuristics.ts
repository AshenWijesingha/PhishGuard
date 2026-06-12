/**
 * On-device content heuristics (M7): urgency/pressure language,
 * credential-solicitation phrasing, payment lures, and brand-keyword vs.
 * off-brand-domain pairing. Pure text analysis — nothing leaves the device.
 */
import { BRANDS } from './brands';
import { parseHost } from './url-heuristics';
import type { Signal } from './scoring';

const URGENCY_PATTERNS: RegExp[] = [
  /account (?:has been |will be |is )?(?:suspended|locked|limited|disabled|deactivated|closed)/i,
  /verify (?:your (?:account|identity|information)|within \d+\s*(?:hours?|days?|minutes?))/i,
  /(?:within|in the next) (?:24|48|72) hours?/i,
  /immediate(?:ly)? (?:action|attention|verification) (?:is )?required/i,
  /unusual (?:sign[- ]?in|login|activity) (?:detected|attempt)/i,
  /your (?:payment|subscription|membership) (?:failed|was declined|could not be processed)/i,
  /final (?:notice|warning|reminder)/i,
  /failure to (?:respond|verify|act|comply)/i,
  /act now|urgent(?:ly)?|expires? (?:today|soon|in \d)/i,
  /you have \(?\d+\)? (?:pending|undelivered|held) (?:messages?|packages?|payments?)/i,
];

const CREDENTIAL_PATTERNS: RegExp[] = [
  /(?:confirm|verify|update|re-?enter|validate) your (?:password|credentials|login|sign[- ]?in)/i,
  /enter your (?:username and password|one[- ]?time (?:code|password)|otp|security code)/i,
  /(?:social security|national insurance) number/i,
  /(?:seed|recovery) phrase|wallet (?:recovery|backup) (?:phrase|words)/i,
  /card (?:number|details) (?:and|with) (?:cvv|security code)/i,
  /login to (?:restore|reactivate|unlock)/i,
];

const PAYMENT_LURE_PATTERNS: RegExp[] = [
  /(?:gift ?card|prepaid card|itunes card|google play card)/i,
  /you(?:'ve| have) (?:won|been selected)/i,
  /claim your (?:refund|reward|prize|payment)/i,
  /refund of [$€£]?\d/i,
  /outstanding (?:invoice|payment|balance) of/i,
  /wire transfer|western union|moneygram/i,
  /pay a (?:small |re-?delivery |customs )?fee/i,
];

export interface ContentAnalysisInput {
  /** Visible text sample (already truncated by the collector). */
  text: string;
  /** Page/email title. */
  title?: string;
  /** Hostname of the page the content is rendered on. */
  pageHostname?: string;
}

export function analyzeContent(input: ContentAnalysisInput): Signal[] {
  const signals: Signal[] = [];
  const haystack = `${input.title ?? ''}\n${input.text}`.slice(0, 20000);

  const urgencyHit = URGENCY_PATTERNS.find((re) => re.test(haystack));
  if (urgencyHit) {
    const match = haystack.match(urgencyHit)?.[0] ?? '';
    signals.push({
      id: 'urgency_language',
      reason: `Pressure language detected (“${match.slice(0, 60)}”) — phishing relies on urgency to rush decisions.`,
      detail: match.slice(0, 120),
    });
  }

  const credHit = CREDENTIAL_PATTERNS.find((re) => re.test(haystack));
  if (credHit) {
    const match = haystack.match(credHit)?.[0] ?? '';
    signals.push({
      id: 'credential_solicitation',
      reason: `The content asks for credentials or secrets (“${match.slice(0, 60)}”).`,
      detail: match.slice(0, 120),
    });
  }

  const lureHit = PAYMENT_LURE_PATTERNS.find((re) => re.test(haystack));
  if (lureHit) {
    const match = haystack.match(lureHit)?.[0] ?? '';
    signals.push({
      id: 'payment_lure',
      reason: `Payment or prize lure detected (“${match.slice(0, 60)}”).`,
      detail: match.slice(0, 120),
    });
  }

  // Brand keyword + off-brand domain pairing
  if (input.pageHostname) {
    const host = parseHost(input.pageHostname);
    if (!host.isIp && host.registrableDomain) {
      const lcHaystack = haystack.toLowerCase();
      for (const brand of BRANDS) {
        if (brand.domains.some((d) => host.registrableDomain === d || host.hostname.endsWith(`.${d}`))) continue;
        // Require the brand to feature prominently: in the title or 3+ mentions.
        const titleHit = (input.title ?? '').toLowerCase().includes(brand.name);
        const mentions = lcHaystack.split(brand.name).length - 1;
        if ((titleHit && mentions >= 1) || mentions >= 3) {
          signals.push({
            id: 'brand_offbrand_mismatch',
            reason: `This page presents itself as ${brand.name}, but it is hosted on “${host.registrableDomain}”, which does not belong to ${brand.name}.`,
            detail: `${brand.name} vs ${host.registrableDomain}`,
          });
          break;
        }
      }
    }
  }

  return signals;
}
