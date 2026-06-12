import { describe, expect, it } from 'vitest';
import { analyzeContent } from '../src/core/content-heuristics';

const ids = (text: string, title?: string, host?: string) =>
  analyzeContent({ text, title, pageHostname: host }).map((s) => s.id);

describe('content heuristics (M7)', () => {
  it('detects urgency/pressure language', () => {
    expect(ids('Your account has been suspended. Verify within 24 hours or lose access.')).toContain('urgency_language');
  });

  it('detects credential solicitation', () => {
    expect(ids('Please confirm your password and enter your one-time code to continue.')).toContain('credential_solicitation');
    expect(ids('Enter your wallet recovery phrase to restore access.')).toContain('credential_solicitation');
  });

  it('detects payment lures', () => {
    expect(ids('You have won! Claim your refund of $250 by purchasing a gift card.')).toContain('payment_lure');
  });

  it('pairs brand keywords with off-brand domains', () => {
    const signals = ids(
      'Welcome to PayPal. Sign in to PayPal to continue. PayPal protects your purchases. paypal everywhere.',
      'PayPal — Log In',
      'secure-verify.example.tk',
    );
    expect(signals).toContain('brand_offbrand_mismatch');
  });

  it('does not flag the brand on its own domain', () => {
    const signals = ids('Welcome to PayPal. PayPal PayPal PayPal.', 'PayPal — Log In', 'www.paypal.com');
    expect(signals).not.toContain('brand_offbrand_mismatch');
  });

  it('stays quiet on benign text', () => {
    expect(ids('Welcome to our gardening blog. Today we discuss tomato varieties.', 'Garden Blog', 'tomatoblog.example')).toEqual([]);
  });
});
