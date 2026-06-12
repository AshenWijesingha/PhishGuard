import { describe, expect, it } from 'vitest';
import { EDUCATION } from '../src/core/education';
import type { SignalId } from '../src/core/scoring';

/** Signals a user can encounter in a blocking modal / banner. */
const USER_FACING: SignalId[] = [
  'homoglyph', 'punycode', 'typosquat', 'brand_in_subdomain', 'excessive_subdomains',
  'ip_literal_host', 'userinfo_in_url', 'suspicious_tld', 'url_shortener',
  'cross_origin_action', 'http_action_from_https', 'login_form_no_https',
  'urgency_language', 'credential_solicitation', 'payment_lure', 'brand_offbrand_mismatch',
  'display_name_mismatch', 'reply_to_divergence', 'link_text_href_mismatch',
  'suspicious_attachment_name', 'young_domain', 'password_reuse', 'threat_intel_hit',
];

describe('education cards (N14)', () => {
  it('covers every user-facing signal', () => {
    for (const id of USER_FACING) {
      expect(EDUCATION[id], `missing education card for ${id}`).toBeDefined();
    }
  });

  it('cards have non-trivial content', () => {
    for (const [id, card] of Object.entries(EDUCATION)) {
      expect(card.title.length, id).toBeGreaterThan(5);
      expect(card.body.length, id).toBeGreaterThan(50);
      expect(card.tip.length, id).toBeGreaterThan(10);
    }
  });
});
